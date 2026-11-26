pub(super) use super::prefix::{Family, Prefix};
use super::{dns, err, io, DnsSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Default, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_sources: Option<crate::sources::Generation>,
    #[serde(with = "super::journal::prefixes")]
    pub prefixes: BTreeMap<Prefix, String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub packed: bool,
    /// Frozen mapping shared by the packet classifier and its per-tunnel FIBs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub marks: BTreeMap<String, u8>,
    /// Non-default RPDB table offsets kept through an exact scoped transfer.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scoped_slots: BTreeMap<String, u8>,
    /// First CIDR identifies a class of source ranges which match the same zones.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "super::journal::source_ranges"
    )]
    pub source_ranges: BTreeMap<Prefix, Vec<Prefix>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub permanent_fences: BTreeSet<String>,
    /// Legacy AWG2_MULTI classified IPv4 payloads even when its DNS listener
    /// received IPv6 queries. Keep that property for this confirmed receipt.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub go_ipv4: bool,
    /// A global IPv6 FORWARD reject observed in Go after the legacy full
    /// firewall was replaced by explicit AWG2_MULTI rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub go_multi_v6_reject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_full: Option<LegacyFull>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_scope: Option<super::legacy_scope::Scope>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_probe: bool,
    /// Mixed AWG2_MULTI rules with at least one unconditional destination.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ordered_default: bool,
    /// Configured cold-standby transports overlapping ordinary destinations.
    /// Only the future AWG UDP socket can bypass the packed RPDB lookup.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub socket_bypass: BTreeSet<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_endpoints: Option<BTreeSet<IpAddr>>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub full_direct: BTreeSet<Prefix>,
    /// A single IPv4 AWG2_MULTI default may apply to specific LAN sources.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub full_sources: BTreeSet<Prefix>,
    #[serde(default, skip_serializing_if = "Backend::legacy")]
    pub firewall: Backend,
    /// OpenWrt's LAN zone. The serialized name predates fw3 support; an
    /// absent value represents the original `lan` chain on either backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fw4_zone: Option<String>,
    /// Effective Keenetic TCP MSS sampled alongside each authenticated peer.
    /// Receipts without this map own the older selector-specific PMTU rules.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "super::mss::read_map")]
    pub mss: BTreeMap<String, u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned: Option<super::learning::Saved>,
    /// Keenetic LAN interfaces whose port-53 queries use the routing DNS listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_bridges: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<dns::Saved>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub killswitch: bool,
    /// Exact source selectors fenced by an unsettled profile transfer.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub temporary_stops: BTreeSet<Selector>,
    /// Previously verified tunnels waiting for their peer after an outage.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub offline: BTreeSet<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "super::journal::route_rows"
    )]
    pub scoped: Vec<(Selector, String)>,
    /// Ordered physical interfaces per selector, after its primary.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "super::journal::reserves"
    )]
    pub reserves: Vec<(Selector, Vec<String>)>,
    /// Only deviations from the primary are stored in the installed receipt.
    /// None means that no authenticated peer currently covers the destination.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "super::journal::route_rows"
    )]
    pub selected: Vec<(Selector, Option<String>)>,
    pub targets: BTreeMap<String, Target>,
    pub revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum LegacyFull {
    Dual,
    Ipv4Only,
    ForwardReject { wan: String, ipv6_endpoint: bool },
}
impl LegacyFull {
    pub(super) fn ipv6_endpoint(cfg: &Value) -> io::Result<bool> {
        let ep = cfg["endpoint"]
            .as_str()
            .ok_or_else(|| err("нет Endpoint одиночного туннеля"))?;
        Ok(ep.parse::<SocketAddr>().is_ok_and(|a| a.is_ipv6())
            || ep.parse::<std::net::Ipv6Addr>().is_ok())
    }
    pub(super) fn valid_wan(s: &str) -> bool {
        !s.is_empty()
            && s.len() < 16
            && s != "lo"
            && !s.starts_with("awg")
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    }
}
pub(super) const MAX_TARGETS: usize = 64;
pub(super) const MAX_FULL_ENDPOINTS: usize = 512;
// The legacy watchdog protects the endpoint and backup transports of the
// active interface and its configured outer VPN. Other profiles are unrelated.
fn single_endpoints(doc: &Value, id: &str, require: bool) -> io::Result<BTreeSet<IpAddr>> {
    let active = doc["servers"]
        .as_array()
        .and_then(|s| s.iter().find(|r| r["id"] == id))
        .ok_or_else(|| err("нет выбранного подключения"))?;
    let outer = active["config"]["client"]["double_tunnel_id"].as_str();
    endpoints_for(doc, require, |r| {
        r["id"] == id || outer.is_some_and(|o| !o.is_empty() && r["id"] == o)
    })
}
#[derive(Default, Clone)]
pub(super) struct Layout {
    pub force_marked: bool,
    pub packed: bool,
    pub marks: BTreeMap<String, u8>,
    pub scoped_slots: BTreeMap<String, u8>,
    pub go_ipv4: bool,
    pub keep_global_scoped: bool,
    pub implicit_go_full_revision: Option<u64>,
    pub go_multi_v6_reject: Option<(u64, String)>,
    pub legacy_full: Option<LegacyFull>,
    pub legacy_revision: Option<u64>,
    pub legacy_scope: Option<super::legacy_scope::Scope>,
}
#[derive(Clone, Copy, Default, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Backend {
    #[default]
    Legacy,
    Fw3,
    Fw4,
}
impl Backend {
    fn legacy(&self) -> bool {
        *self == Self::Legacy
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    pub source: Prefix,
    pub dest: Prefix,
}
impl Selector {
    fn overlaps(self, other: Self) -> bool {
        self.source.overlaps(other.source) && self.dest.overlaps(other.dest)
    }
    fn covers(self, b: Self) -> bool {
        self.source.covers(b.source) && self.dest.covers(b.dest)
    }
    fn uncovered(self, earlier: &BTreeSet<Self>, limit: usize) -> io::Result<Vec<Self>> {
        let mut parts = vec![self];
        let mut next = Vec::new();
        for &old in earlier.iter().filter(|old| self.overlaps(**old)) {
            for part in parts.drain(..) {
                part.excluding(old, &mut next);
                if next.len() > limit {
                    return Err(capacity("слишком много пересекающихся сетей IP"));
                }
            }
            std::mem::swap(&mut parts, &mut next);
            if parts.is_empty() {
                break;
            }
        }
        Ok(parts)
    }
    fn excluding(self, old: Self, out: &mut Vec<Self>) {
        if !self.overlaps(old) {
            out.push(self);
            return;
        }
        self.source
            .outside(old.source, |source| out.push(Self { source, ..self }));
        let source = self.source.max_by_length(old.source);
        self.dest
            .outside(old.dest, |dest| out.push(Self { source, dest }));
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub id: String,
    pub public_key: String,
    pub mtu: u16,
}
pub(super) fn iface_ok(s: &str) -> bool {
    s.len() < 16
        && s.strip_prefix("awg")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}
impl Plan {
    pub(super) fn ipv6_reject_wan(&self) -> Option<&str> {
        match &self.legacy_full {
            Some(LegacyFull::ForwardReject { wan, .. }) => Some(wan),
            _ => self.go_multi_v6_reject.as_deref(),
        }
    }
    pub(super) fn legacy_primary(&self) -> Option<(&str, &Target)> {
        self.legacy_full.as_ref()?;
        let iface = self.prefixes.get(&Family::V4.any())?;
        let target = self.targets.get(iface)?;
        (self.targets.len() == 1).then_some((iface, target))
    }

    // Explicit Go catch-all zones use the IPv4-only multi classifier.
    // A native dual-stack blanket or an observed single AWG2_MARK belongs
    // to one saved primary, including when a different server is selected
    // in the editor after commit.
    pub(super) fn permanent_full_inner(&self, doc: &Value) -> Option<String> {
        if self.full_endpoints.is_none() || self.go_ipv4 && self.legacy_full.is_none() {
            return None;
        }
        let iface = self.prefixes.get(&Family::V4.any())?;
        let owner = &self.targets.get(iface)?.id;
        doc["servers"].as_array()?.iter().find(|r| {
            r["id"].as_str() == Some(owner) && r["config"]["client"]["double_tunnel_mode"] == "permanent"
        }).map(|_| iface.clone())
    }
    pub(super) fn upgrade_permanent_full(&self, doc: &Value) -> io::Result<Option<Self>> {
        let Some(inner) = self.permanent_full_inner(doc) else { return Ok(None); };
        if self.killswitch && self.reserves.is_empty() {
            return Ok(None);
        }
        let mut fixed = self.clone();
        fixed.killswitch = true;
        fixed.reserves.clear();
        fixed.selected.clear();
        fixed.offline.clear();
        fixed.targets.retain(|iface, _| iface == &inner);
        fixed.mss.retain(|iface, _| iface == &inner);
        fixed.full_endpoints = Some(single_endpoints(doc, &fixed.targets[&inner].id, true)?);
        Ok(Some(fixed))
    }
    pub(super) fn protected(&self, iface: &str) -> bool {
        self.killswitch || self.permanent_fences.contains(iface)
    }
    pub(super) fn has_protection(&self) -> bool {
        self.killswitch || !self.permanent_fences.is_empty() || !self.temporary_stops.is_empty()
    }
    pub(super) fn matches_source(&self, s: Selector, address: IpAddr) -> bool {
        let Some(nets) = self.source_ranges.get(&s.source) else {
            return s.source.contains(address);
        };
        let host = Prefix::host(address);
        let index = nets.partition_point(|p| p <= &host);
        index > 0 && nets[index - 1].contains(address)
    }
    fn has_host(&self, ip: IpAddr) -> bool {
        let p = Prefix::host(ip);
        self.prefixes.contains_key(&p) || self.scoped.iter().any(|(s, _)| s.dest == p)
    }
    pub(super) fn assign_marks(&mut self, previous: &BTreeMap<String, u8>) -> io::Result<()> {
        let mut slots = BTreeMap::new();
        // Retired interfaces still carry the previous classifier until the
        // single mangle transaction commits. Keep their slots unavailable.
        let mut occupied = previous.values().copied().collect::<BTreeSet<_>>();
        for iface in self.targets.keys() {
            let slot = if let Some(old) = previous.get(iface) {
                *old
            } else {
                let free = (1..=128)
                    .find(|n| !occupied.contains(n))
                    .ok_or_else(|| err("не хватает таблиц переключения зон AWG"))?;
                occupied.insert(free);
                free
            };
            slots.insert(iface.clone(), slot);
        }
        self.marks = slots;
        Ok(())
    }
    pub(super) fn scoped_slot(&self, iface: &str) -> u8 {
        self.scoped_slots.get(iface).copied().unwrap_or_else(|| {
            self.targets
                .keys()
                .position(|target| target == iface)
                .expect("known scoped target") as u8
        })
    }
    fn assign_scoped_slots(&mut self, mut slots: BTreeMap<String, u8>) -> io::Result<()> {
        slots.retain(|iface, _| self.targets.contains_key(iface));
        let mut occupied = slots.values().copied().collect::<BTreeSet<_>>();
        for iface in self.targets.keys() {
            if let std::collections::btree_map::Entry::Vacant(target) = slots.entry(iface.clone()) {
                let slot = (0..MAX_TARGETS as u8)
                    .find(|slot| occupied.insert(*slot))
                    .ok_or_else(|| err("не хватает таблиц защищённых зон AWG"))?;
                target.insert(slot);
            }
        }
        if slots.values().copied().ne(0..slots.len() as u8) {
            self.scoped_slots = slots;
        }
        Ok(())
    }
    pub(super) fn probe_iface(&self) -> Option<&str> {
        let v4 = Family::V4.any();
        self.legacy_probe.then_some(())?;
        self.effective(
            Selector {
                source: v4,
                dest: v4,
            },
            self.prefixes.get(&v4)?,
        )
    }
    /// Check the actual serialized generation before stopping Go. The
    /// journal accounts separately for distinct generations in a transition.
    pub(super) fn check_handoff_size(&self) -> io::Result<()> {
        super::journal::encoded_size(self).map(|_| ())
    }
    pub fn layout(&self) -> Layout {
        Layout {
            force_marked: false,
            packed: self.packed,
            marks: self.marks.clone(),
            scoped_slots: self.scoped_slots.clone(),
            go_ipv4: self.go_ipv4,
            keep_global_scoped: !self.scoped.is_empty()
                && self.scoped.iter().all(|(selector, _)| selector.source.any()),
            implicit_go_full_revision: (self.go_ipv4 && self.full_endpoints.is_some() && self.legacy_full.is_none()).then_some(self.revision),
            go_multi_v6_reject: self
                .go_multi_v6_reject
                .clone()
                .map(|wan| (self.revision, wan)),
            legacy_full: self.legacy_full.clone(),
            legacy_revision: self.legacy_full.as_ref().map(|_| self.revision),
            legacy_scope: self.legacy_scope.clone(),
        }
    }
    fn verify_dns_bridges(&self, bridges: &[String]) -> io::Result<()> {
        if !bridges.is_empty()
            && (self.learned.is_none()
                || self.legacy_full.is_some()
                    && self.legacy_scope.as_ref().is_none_or(|scope| !scope.learner_wanted())
                || self.firewall != Backend::Legacy
                || bridges.len() > 128
                || bridges.windows(2).any(|p| p[0] >= p[1])
                || !bridges.iter().all(|name| super::valid_dns_bridge(name)))
        {
            return Err(err("неверный список LAN-мостов перехвата DNS"));
        }
        Ok(())
    }
    pub(super) fn set_dns_bridges(&mut self, bridges: &[String]) -> io::Result<()> {
        self.verify_dns_bridges(bridges)?;
        self.dns_bridges = bridges.to_vec();
        Ok(())
    }
    pub(super) fn reserves_for(&self, s: Selector) -> &[String] {
        self.reserves
            .binary_search_by_key(&s, |(key, _)| *key)
            .map(|i| self.reserves[i].1.as_slice())
            .unwrap_or_default()
    }
    pub fn effective<'a>(&'a self, s: Selector, primary: &'a str) -> Option<&'a str> {
        match self.selected.binary_search_by_key(&s, |(key, _)| *key) {
            Ok(i) => self.selected[i].1.as_deref(),
            Err(_) => (!self.offline.contains(primary)).then_some(primary),
        }
    }
    pub fn fully_live(&self) -> bool {
        self.offline.is_empty()
            && self.selected.iter().all(|(s, v)| {
                v.is_some() || self.full_endpoints.is_some() && s.dest.family() == Family::V6
            })
    }
    /// A fixed recovery target that cannot authorize any forwarding, regardless
    /// of the sequence in which peers come back up.
    pub fn guards_only(&self) -> Self {
        if !self.has_protection() || self.flows().next().is_none() {
            return self
                .go_multi_v6_reject
                .as_ref()
                .map_or_else(Self::default, |wan| Self {
                    go_ipv4: true,
                    go_multi_v6_reject: Some(wan.clone()),
                    revision: self.revision,
                    ..Self::default()
                });
        }
        let mut guards = self.clone();
        guards.dns_bridges.clear();
        guards.mss.clear();
        guards.selected.clear();
        guards.offline = guards.targets.keys().cloned().collect();
        guards
    }
    pub fn reserve_chains(&self) -> BTreeMap<&str, BTreeSet<Vec<&str>>> {
        let mut chains = BTreeMap::<_, BTreeSet<_>>::new();
        for (s, primary) in self.flows() {
            let reserves = self.reserves_for(s);
            if !reserves.is_empty() {
                chains
                    .entry(self.targets[primary].id.as_str())
                    .or_default()
                    .insert(
                        reserves
                            .iter()
                            .map(|i| self.targets[i].id.as_str())
                            .collect(),
                    );
            }
        }
        chains
    }
    pub fn active_reserves(&self) -> BTreeSet<&str> {
        self.selected
            .iter()
            .filter_map(|(_, i)| i.as_ref())
            .map(|i| self.targets[i].id.as_str())
            .collect()
    }
    pub fn park(&mut self, selectors: &[Selector]) {
        if !selectors.is_empty() {
            let mut selected = std::mem::take(&mut self.selected)
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            selected.extend(selectors.iter().map(|&s| (s, None)));
            self.selected = selected.into_iter().collect();
            if self.go_ipv4 && self.legacy_full.is_none() && !self.mss.is_empty() {
                let mut mss = std::mem::take(&mut self.mss);
                let still_used = self.flows().filter_map(|(s, i)| self.effective(s, i))
                    .collect::<BTreeSet<_>>();
                mss.retain(|iface, _| still_used.contains(iface.as_str()));
                self.mss = mss;
            }
        }
    }
    pub fn flows(&self) -> impl Iterator<Item = (Selector, &str)> {
        self.prefixes
            .iter()
            .map(|(dest, iface)| {
                (
                    Selector {
                        source: dest.family().any(),
                        dest: *dest,
                    },
                    iface.as_str(),
                )
            })
            .chain(
                self.scoped
                    .iter()
                    .map(|(sel, iface)| (*sel, iface.as_str())),
            )
    }
    pub fn validate(&self) -> io::Result<()> {
        if self
            .fw4_zone
            .as_deref()
            .is_some_and(|z| z == "lan" || !super::inventory::valid_zone(self.firewall, z))
        {
            return Err(err("неверная зона OpenWrt в журнале маршрутов"));
        }
        if !self.mss.is_empty()
            && (self.firewall != Backend::Legacy
                || self.mss.len() > MAX_TARGETS
                || self.mss.iter().any(|(iface, mss)| {
                    !self.targets.contains_key(iface) || !(536..=8960).contains(mss)
                }))
        {
            return Err(err("неверный журнал MSS туннелей AWG"));
        }
        if self
            .permanent_fences
            .iter()
            .any(|i| !self.marks.contains_key(i))
        {
            return Err(err("неизвестная таблица постоянного AWG"));
        }
        if !self.source_ranges.is_empty() {
            let total = self.source_ranges.values().map(Vec::len).sum::<usize>();
            let mut all = Vec::with_capacity(total.min(super::packed::LIMIT));
            if self.marks.is_empty()
                || total > super::packed::LIMIT
                || self.source_ranges.iter().any(|(k, v)| {
                    v.first() != Some(k)
                        || v.windows(2).any(|w| w[0] >= w[1])
                        || v.iter().any(|p| p.family() != k.family())
                })
            {
                return Err(err("повреждены сети источников маркированных зон"));
            }
            all.extend(self.source_ranges.values().flatten().copied());
            all.sort_unstable();
            if all.windows(2).any(|w| w[0].overlaps(w[1]))
                || self
                    .scoped
                    .iter()
                    .any(|(s, _)| !self.source_ranges.contains_key(&s.source))
            {
                return Err(err("группы источников политики пересекаются"));
            }
        }
        if !self.marks.is_empty()
            && (!self.packed
                || self.marks.keys().ne(self.targets.keys())
                || self.marks.values().any(|s| !(1..=128).contains(s))
                || self.marks.values().copied().collect::<BTreeSet<_>>().len() != self.marks.len())
        {
            return Err(err("повреждён журнал маркированных таблиц AWG"));
        }
        if !self.scoped_slots.is_empty()
            && (self.packed
                || self.scoped.is_empty()
                || self.full_endpoints.is_some()
                || self.scoped_slots.keys().ne(self.targets.keys())
                || self.scoped_slots.values().any(|&slot| usize::from(slot) >= MAX_TARGETS)
                || self.scoped_slots.values().collect::<BTreeSet<_>>().len() != self.scoped_slots.len())
        {
            return Err(err("повреждён журнал таблиц зон AWG"));
        }
        if !self.marks.is_empty()
            && self
                .prefixes
                .keys()
                .zip(self.prefixes.keys().skip(1))
                .any(|(a, b)| a.overlaps(*b))
        {
            return Err(err("перекрывающиеся наборы маркированных зон AWG"));
        }
        self.verify_dns_bridges(&self.dns_bridges)?;
        let scoped_learner = if let Some(scope) = &self.legacy_scope {
            if self.legacy_full.is_none() {
                return Err(err("нет владельца правил клиентов Go"));
            }
            scope.valid()?;
            if scope.learner_wanted() != self.learned.is_some()
                || self.learned.as_ref().is_some_and(|saved| !scope.tracks_members(&saved.members))
            {
                return Err(err("DNS-адрес не принадлежит подтверждённой зоне старого туннеля"));
            }
            scope.learner_wanted()
        } else {
            false
        };
        if self.ordered_default
            && (!self.go_ipv4
                || self.legacy_full.is_some()
                || self.full_endpoints.is_some()
                || self.firewall != Backend::Legacy)
        {
            return Err(err(
                "несовместимые параметры зонального маршрута по умолчанию",
            ));
        }
        if self.go_ipv4
            && (self.flows().any(|(s, _)| s.dest.family() != Family::V4)
                || !scoped_learner && self
                    .learned
                    .as_ref()
                    .is_some_and(|s| s.members.iter().any(|m| !m.ip.is_ipv4())))
        {
            return Err(err(
                "в журнале IPv4-маршрутизации Go обнаружены назначения IPv6",
            ));
        }
        if self.go_multi_v6_reject.as_deref().is_some_and(|wan| {
            !self.go_ipv4
                || self.legacy_full.is_some()
                || self.firewall != Backend::Legacy
                || !LegacyFull::valid_wan(wan)
        }) {
            return Err(err("неверное сохранённое правило AWG2_MULTI для IPv6"));
        }
        if self.dns.is_some() && self.learned.is_some() {
            return Err(err("несовместимые режимы DNS в журнале маршрутизации"));
        }
        if let Some(learned) = &self.learned {
            learned.validate()?;
        }
        if let Some(dns) = &self.dns {
            dns.snapshot.validate(self.revision)?;
            if dns.source_hash.len() != 64
                || !dns.source_hash.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(err("повреждена идентичность DNS-политики"));
            }
        }
        let known: BTreeMap<_, _> = self.flows().collect();
        let full = self.full_endpoints.is_some();
        if let Some(first) = self.temporary_stops.first() {
            if self.killswitch
                || full
                || self.packed
                || self.ordered_default
                || self.firewall != Backend::Legacy
                || !matches!(self.targets.len(), 1 | 2)
                || !self.reserves.is_empty()
                || self.learned.is_none()
                || first.source.family() != Family::V4
                || !first.source.is_host()
                || self.temporary_stops.iter().any(|selector| {
                    selector.source != first.source || !known.contains_key(selector)
                })
                || self.scoped.iter().any(|(selector, _)| {
                    selector.source == first.source && !self.temporary_stops.contains(selector)
                })
            {
                return Err(err("неверная временная защита при переносе профиля"));
            }
        }
        if self.legacy_probe
            && !matches!(
                self.legacy_full,
                Some(LegacyFull::Dual | LegacyFull::ForwardReject { .. })
            )
        {
            return Err(err("неверная запись контрольного маршрута IPv6"));
        }
        if let Some(old) = &self.legacy_full {
            if !full
                || !self.full_direct.is_empty()
                || !self.full_sources.is_empty()
                || !self.reserves.is_empty()
                || match old {
                    LegacyFull::Dual => self.go_ipv4,
                    LegacyFull::Ipv4Only => !self.go_ipv4,
                    LegacyFull::ForwardReject { wan, .. } => {
                        !self.go_ipv4 || !LegacyFull::valid_wan(wan)
                    }
                }
            {
                return Err(err("неверный журнал одиночного полного туннеля Go"));
            }
        }
        if !self.socket_bypass.is_empty()
            && (!self.go_ipv4
                || !self.packed
                || self.socket_bypass.len() > 512
                || self
                    .socket_bypass
                    .iter()
                    .any(|ip| !ip.is_ipv4() || !self.has_host(*ip)))
        {
            return Err(err("неверный список транспортов резервных AWG-сокетов"));
        }
        if !self.full_direct.is_empty()
            && (!self.go_ipv4
                || self.full_endpoints.is_none()
                || self.full_direct.len() > 256
                || self
                    .full_direct
                    .iter()
                    .any(|net| net.family() != Family::V4 || net.any()))
        {
            return Err(err("неверные прямые исключения маршрута по умолчанию"));
        }
        if !self.full_sources.is_empty()
            && (!self.go_ipv4
                || self.full_endpoints.is_none()
                || self.full_sources.len() > 64
                || self
                    .full_sources
                    .iter()
                    .any(|p| p.any() || p.family() != Family::V4 || !p.safe()))
        {
            return Err(err("неверные источники зонального маршрута по умолчанию"));
        }
        if let Some(exempt) = &self.full_endpoints {
            let defaults = if self.go_ipv4 {
                self.prefixes.len() == 1 && self.prefixes.contains_key(&Family::V4.any())
            } else {
                self.prefixes.len() == 2
                    && self.prefixes.contains_key(&Family::V4.any())
                    && self.prefixes.get(&Family::V4.any()) == self.prefixes.get(&Family::V6.any())
            };
            if exempt.is_empty()
                || exempt.len() > MAX_FULL_ENDPOINTS
                || !self.scoped.is_empty()
                || self.packed
                || self.dns.is_some()
                || self.learned.is_some() && !scoped_learner
                || self.firewall != Backend::Legacy
                || !defaults
            {
                return Err(err("повреждена политика полного туннеля"));
            }
        }
        if self.packed
            && (self.marks.is_empty() && (self.killswitch || !self.scoped.is_empty())
                || self.firewall != Backend::Legacy)
            || self.prefixes.len() + self.scoped.len()
                > if self.packed {
                    if self.marks.is_empty() {
                        super::packed::OLD_LIMIT
                    } else {
                        super::packed::LIMIT
                    }
                } else if self.ordered_default {
                    512
                } else {
                    128
                }
            || !self.offline.is_empty() && !self.has_protection()
            || self
                .offline
                .iter()
                .any(|iface| !self.targets.contains_key(iface))
            || !self.prefixes.is_empty() && !self.scoped.is_empty()
            || self.marks.is_empty()
                && self
                    .scoped
                    .iter()
                    .enumerate()
                    .any(|(i, (s, _))| self.scoped[..i].iter().any(|(prev, _)| s.overlaps(*prev)))
            || !self.marks.is_empty()
                && (self.scoped.windows(2).any(|p| {
                    p[0].0 >= p[1].0
                        || p[0].0.source == p[1].0.source && p[0].0.dest.overlaps(p[1].0.dest)
                }) || !self.scoped.is_empty() && self.source_ranges.is_empty())
            || self.targets.len() > MAX_TARGETS
            || self.reserves.len() > known.len()
            || self.selected.len() > known.len()
            || self.reserves.windows(2).any(|p| p[0].0 >= p[1].0)
            || self.selected.windows(2).any(|p| p[0].0 >= p[1].0)
            || self.reserves.iter().any(|(s, list)| {
                let Some(&primary) = known.get(s) else {
                    return true;
                };
                list.is_empty()
                    || list.len() >= self.targets.len()
                    || list.iter().enumerate().any(|(i, iface)| {
                        iface == primary
                            || !self.targets.contains_key(iface)
                            || list[..i].contains(iface)
                    })
            })
            || self.selected.iter().any(|(s, alt)| {
                !known.contains_key(s)
                    || alt
                        .as_ref()
                        .is_some_and(|i| !self.reserves_for(*s).contains(i))
                    || alt.is_none()
                        && !self.protected(known[s])
                        && !self.temporary_stops.contains(s)
                        && self.reserves.is_empty()
                        && !full
            })
            || self.flows().any(|(s, i)| {
                s.source.family() != s.dest.family()
                    || !s.dest.safe() && !(full && s.dest.any())
                    || !self.targets.contains_key(i)
            })
            || self.targets.iter().any(|(i, t)| {
                !iface_ok(i)
                    || t.public_key.len() != 44
                    || !(576..=9000).contains(&t.mtu)
                    || !crate::model::reference(&t.id)
                    || !known.values().any(|v| *v == i)
                        && !self.reserves.iter().any(|(_, list)| list.contains(i))
            })
        {
            return Err(err(
                "неверный или слишком большой набор статических маршрутов AWG",
            ));
        }
        if !self.marks.is_empty() {
            super::marked::check_size(self)?;
        }
        Ok(())
    }
    pub fn empty(&self) -> bool {
        self.prefixes.is_empty()
            && self.scoped.is_empty()
            && self.dns.is_none()
            && self.learned.is_none()
            && self.go_multi_v6_reject.is_none()
    }
}
fn prefixes<'a>(
    raw: impl IntoIterator<Item = &'a String>,
    limit: usize,
) -> io::Result<BTreeSet<Prefix>> {
    let mut nets = BTreeSet::new();
    for value in raw {
        nets.insert(value.trim().parse()?);
        if nets.len() > limit {
            return Err(err(format!("предел сетей в зоне: {limit}")));
        }
    }
    Ok(nets)
}

// A direct exception claims its pairs without installing a route. Only the
// previously unmatched portion of a later tunnel rule becomes kernel state.
fn capacity(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, message.into())
}
struct Selection<'a> {
    global: bool,
    ordered_default: bool,
    scope: Option<&'a BTreeSet<Prefix>>,
}
fn select_zone(
    z: &crate::Zone,
    snapshot: Option<(&DnsSnapshot, (bool, bool))>,
    members: &[super::learning::Member],
    earlier: &mut BTreeSet<Selector>,
    installed: usize,
    selection: Selection<'_>,
) -> io::Result<Vec<Selector>> {
    let Selection {
        global,
        ordered_default,
        scope,
    } = selection;
    let max_nets = super::packed::ZONE_LIMIT;
    let mut sources = if let Some(reps) = scope {
        reps.clone()
    } else {
        prefixes(&z.source_ips, max_nets)?
    };
    let mut dests = prefixes(
        z.ips.iter().filter(|v| !crate::model::catch_all(v)),
        max_nets,
    )?;
    if ordered_default && z.only_catch_all() {
        dests.insert(Family::V4.any());
    }
    // Go accepts IP/CIDR entries alongside names in the imported domains list.
    for entry in z
        .domains
        .iter()
        .filter(|v| crate::model::ipish(v) && !crate::model::catch_all(v))
    {
        dests.insert(entry.parse()?);
        if dests.len() > max_nets {
            return Err(err(format!("предел сетей в зоне: {max_nets}")));
        }
    }
    for member in members {
        dests.insert(Prefix::host(member.ip));
    }
    if let Some((snapshot, (v4, v6))) = snapshot {
        for raw in z
            .domains
            .iter()
            .filter(|v| !crate::model::ipish(v) && !crate::model::catch_all(v))
        {
            let host = dns::name(raw)?;
            dests.extend(
                snapshot.answers[&host]
                    .iter()
                    .filter(|ip| if ip.is_ipv4() { v4 } else { v6 })
                    .copied()
                    .map(Prefix::host),
            );
        }
    }
    if dests.len() > super::packed::ZONE_LIMIT {
        return Err(err("в одной зоне допускается до 65 536 сетей"));
    }
    if sources.is_empty() {
        sources.extend(dests.iter().map(|d| d.family().any()));
    }
    // A large source-scoped list may describe only a few adjacent ranges.
    // Compact within this rule only, preserving every earlier decision and
    // the independent leases kept by the DNS snapshot.
    if !global && dests.len() > 256 {
        dests = Prefix::compact(dests);
    }
    if scope.is_none() && sources.len() > 256 {
        sources = Prefix::compact(sources);
    }
    let pairs = sources
        .iter()
        .map(|s| dests.iter().filter(|d| d.family() == s.family()).count())
        .sum::<usize>();
    let limit = if global {
        super::packed::LIMIT
    } else if ordered_default {
        512
    } else {
        128
    };
    if pairs > limit.max(256) {
        return Err(capacity(format!(
            "превышен предел {} пар источник–назначение на зону",
            limit.max(256)
        )));
    }
    let mut pending = Vec::new();
    for source in sources {
        for &dest in dests.iter().filter(|d| d.family() == source.family()) {
            let sel = Selector { source, dest };
            // For an unscoped host, only its CIDR ancestors can overlap it.
            // DNS updates usually merge thousands of these exact addresses.
            if if global {
                dest.ancestors()
                    .any(|dest| earlier.contains(&Selector { source, dest }))
            } else {
                earlier.iter().any(|p| p.covers(sel))
            } {
                continue;
            }
            if z.direction() == "tunnel" {
                if global {
                    // Prefix order groups all descendants contiguously.
                    // No ancestor claimed this range; subtract only its
                    // descendants, without scanning other zones' networks.
                    let mut uncovered = vec![sel];
                    while let Some(part) = uncovered.pop() {
                        let Some(&child) =
                            earlier.range(part..).next().filter(|c| part.covers(**c))
                        else {
                            pending.push(part);
                            if pending.len() + installed > limit {
                                return Err(capacity(
                                    "слишком много селекторов IP в политике маршрутов",
                                ));
                            }
                            continue;
                        };
                        part.dest
                            .outside(child.dest, |dest| uncovered.push(Selector { source, dest }));
                    }
                } else {
                    pending.extend(sel.uncovered(earlier, limit.max(256))?);
                }
                if pending.len() + installed > limit {
                    return Err(capacity("слишком много селекторов IP в политике маршрутов"));
                }
            }
            if global && !dest.is_host() {
                let subs: Vec<_> = earlier
                    .range(sel..)
                    .take_while(|p| sel.covers(**p))
                    .copied()
                    .collect();
                for sub in subs {
                    earlier.remove(&sub);
                }
            } else if !global {
                earlier.retain(|p| !sel.covers(*p));
            }
            earlier.insert(sel);
            if earlier.len() > limit.max(256) + if global { 520 } else { 0 } {
                return Err(capacity(format!(
                    "превышен предел {} пар IP в политике",
                    limit.max(256)
                )));
            }
        }
    }
    Ok(pending)
}
pub struct LivePeer {
    pub ipv6_reachable: bool,
    pub nested_mtu: Option<u16>,
    pub endpoint: SocketAddr,
    pub allowed: Vec<String>,
    pub socket_mark: u32,
    pub(super) prefer_ordinary: bool,
    pub(super) nested_transport: Option<nfqws2_awg_profile::RoutedNestedTransport>,
    pub(super) direct_backup: Option<nfqws2_awg_profile::RoutedDirectBackup>,
    pub(super) endpoint_predecessor: Option<nfqws2_awg_profile::RoutedEndpointPredecessor>,
    pub(super) fresh_bound_ipv6_probe: Option<bool>,
    pub(super) active_replacement_peer: Option<Box<nfqws2_awg_profile::ActiveReplacementPeer>>,
}
impl LivePeer {
    pub fn with_ordinary_preference(mut self, prefer: bool) -> Self {
        self.prefer_ordinary = prefer;
        self
    }

    pub fn with_active_replacement_peer(
        mut self,
        peer: Option<nfqws2_awg_profile::ActiveReplacementPeer>,
    ) -> Self {
        self.active_replacement_peer = peer.map(Box::new);
        self
    }

    pub fn with_fresh_bound_ipv6_probe(mut self, outcome: Option<bool>) -> Self {
        self.fresh_bound_ipv6_probe = outcome;
        self
    }
    pub fn with_endpoint_predecessor(
        mut self,
        witness: Option<nfqws2_awg_profile::RoutedEndpointPredecessor>,
    ) -> Self {
        self.endpoint_predecessor = witness;
        self
    }
    pub fn with_direct_backup(
        mut self,
        witness: Option<nfqws2_awg_profile::RoutedDirectBackup>,
    ) -> Self {
        self.direct_backup = witness;
        self
    }
    pub fn with_nested_transport(mut self, witness: Option<nfqws2_awg_profile::RoutedNestedTransport>) -> Self {
        self.nested_transport = witness;
        self
    }
    /// Read only after the UAPI peer and its physical interface were verified.
    pub fn from_uapi(
        root: &std::path::Path,
        iface: &str,
        endpoint: SocketAddr,
        allowed: Vec<String>,
        socket_mark: u32,
        ipv6_reachable: bool,
    ) -> io::Result<Self> {
        let nested_mtu = if socket_mark >> 28 == 0xa {
            if !iface_ok(iface) {
                return Err(err("неверный интерфейс вложенного AWG"));
            }
            let path = root.join("sys/class/net").join(iface).join("mtu");
            let mtu = std::fs::read_to_string(path)?
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|n| (576..=9000).contains(n))
                .ok_or_else(|| err("неверный действующий MTU вложенного AWG"))?;
            Some(mtu)
        } else {
            None
        };
        Ok(Self {
            endpoint,
            allowed,
            socket_mark,
            ipv6_reachable,
            nested_mtu,
            prefer_ordinary: false,
            nested_transport: None,
            direct_backup: None,
            endpoint_predecessor: None,
            fresh_bound_ipv6_probe: None,
            active_replacement_peer: None,
        })
    }
}
pub(super) fn profile<'a>(
    doc: &'a Value,
    rows: &'a [Value],
    id: &str,
) -> io::Result<(&'a Value, String, Target)> {
    let (index, row) = rows
        .iter()
        .enumerate()
        .find(|(_, r)| r["id"] == id)
        .ok_or_else(|| err("неизвестный туннель правила"))?;
    let c = &row["config"];
    let wire = if row["applied_config"].is_object() {
        &row["applied_config"]
    } else {
        c
    };
    if c["client"]["double_tunnel_id"]
        .as_str()
        .is_some_and(|v| !v.is_empty())
        || !matches!(
            c["client"]["double_tunnel_mode"].as_str(),
            None | Some("" | "off" | "last_resort")
        )
    {
        // An optional outer tunnel is a transport choice. The payload still
        // uses this same TUN and authenticated peer in either transport mode.
        nfqws2_awg_profile::FailoverGraph::load(doc)?;
    }
    let iface = wire["client_iface"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("awg{index}"));
    if !iface_ok(&iface) {
        return Err(err("неверный интерфейс AWG"));
    }
    let target = Target {
        id: id.to_owned(),
        public_key: wire["public_key"].as_str().unwrap_or_default().into(),
        mtu: nfqws2_awg_profile::tunnel_mtu(wire, &c["routing"])
            .try_into()
            .map_err(|_| err("неверный MTU туннеля"))?,
    };
    Ok((wire, iface, target))
}
fn grants(live: LivePeer, endpoints: &mut BTreeSet<IpAddr>) -> io::Result<Vec<Prefix>> {
    endpoints.insert(live.endpoint.ip().to_canonical());
    live.allowed.iter().map(|s| s.parse()).collect()
}

pub(super) fn verify_nested_path(
    k: &super::Kernel<'_>,
    iface: &str,
    outer: &str,
    live: &LivePeer,
) -> io::Result<()> {
    verify_nested_path_with_source(k, iface, outer, live, None)
}

pub(super) fn verify_nested_path_with_source(
    k: &super::Kernel<'_>,
    iface: &str,
    outer: &str,
    live: &LivePeer,
    source: Option<IpAddr>,
) -> io::Result<()> {
    let invalid = || err("сокет полного туннеля не подтверждён на выбранном внешнем AWG");
    let (mark, _) = nfqws2_awg_profile::nested_socket_selector(iface)?;
    if live.socket_mark != mark {
        return Err(invalid());
    }
    verify_nested_socket_path(k, iface, outer, live.endpoint.ip().to_canonical(), source)
}

pub(super) fn verify_nested_socket_path(
    k: &super::Kernel<'_>,
    iface: &str,
    outer: &str,
    address: IpAddr,
    source: Option<IpAddr>,
) -> io::Result<()> {
    let invalid = || err("сокет полного туннеля не подтверждён на выбранном внешнем AWG");
    if iface == outer {
        return Err(invalid());
    }
    let (mark, table) = nfqws2_awg_profile::nested_socket_selector(iface)?;
    let family = Family::of(address);
    let rules = k.listing(family, &["rule", "show"])?;
    if super::full::socket_pairs(&rules, &BTreeMap::from([(mark, table)]))?.len() != 2 {
        return Err(invalid());
    }
    let path = k.call(
        "ip",
        &[
            family.flag(), "route", "get", &address.to_string(),
            "mark", &format!("0x{mark:x}"),
        ],
    )?;
    let words: Vec<_> = path.lines().next().unwrap_or_default().split_ascii_whitespace().collect();
    if !words.windows(2).any(|w| w == ["dev", outer])
        || !words.windows(2).any(|w| w[0] == "table" && w[1].parse::<u32>().ok() == Some(table))
        || source.is_some_and(|source| !words.windows(2).any(|w| w[0] == "src" && w[1].parse::<IpAddr>().ok() == Some(source)))
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn build(
    db: &nfqws2_store::Store,
    doc: &Value,
    snapshot: Option<&DnsSnapshot>,
    approved: bool,
    k: &super::Kernel<'_>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<(Plan, BTreeSet<IpAddr>)> {
    build_live(db, doc, snapshot, approved, false, k, peer)
}

pub(super) fn build_initial(
    db: &nfqws2_store::Store,
    doc: &Value,
    snapshot: Option<&DnsSnapshot>,
    k: &super::Kernel<'_>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<(Plan, BTreeSet<IpAddr>)> {
    build_live(db, doc, snapshot, false, true, k, peer)
}

fn build_live(
    db: &nfqws2_store::Store,
    doc: &Value,
    snapshot: Option<&DnsSnapshot>,
    approved: bool,
    initial: bool,
    k: &super::Kernel<'_>,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<(Plan, BTreeSet<IpAddr>)> {
    let mut routing = crate::sources::current(db, doc)?;
    let mut samples = BTreeMap::new();
    let mut layout = Layout::default();
    if initial && snapshot.is_none() {
        if let Some(zone) = super::handoff::implicit_multi::native_draft(doc, &routing) {
            let boot = super::boot_id(k)?;
            let rows = doc["servers"]
                .as_array()
                .ok_or_else(|| err("нет списка серверов AWG"))?;
            let mut families = Vec::new();
            for id in std::iter::once(&zone.tunnel_id).chain(&zone.fallback_tunnel_ids) {
                let (wire, iface, target) = profile(doc, rows, id)?;
                let sample = peer(wire, &iface);
                families.push(sample.as_ref().ok().and_then(|live| {
                    witnessed_native_families(k, wire, &iface, &boot, &target, live)
                }));
                if samples.insert(iface, sample).is_some() {
                    return Err(err("у подключений полного туннеля совпадает интерфейс"));
                }
            }
            let compatible = match families.as_slice() {
                [Some(NativeFullFamilies::Dual), Some(NativeFullFamilies::Dual)] => true,
                [Some(NativeFullFamilies::Ipv4), Some(NativeFullFamilies::Ipv4)] => {
                    let wan = fresh_full_ipv6_reject(k);
                    layout.go_ipv4 = wan.is_some();
                    layout.go_multi_v6_reject =
                        wan.map(|wan| (doc["routing_revision"].as_u64().unwrap_or_default(), wan));
                    layout.go_ipv4
                }
                _ => false,
            };
            if compatible {
                // Compile the same ephemeral IPv4 classifier that confirmation
                // and recovery rebuild for the already recognized Go geometry.
                routing.zones.push(zone);
            }
        }
    }
    let plan = compile_effective(doc, routing, snapshot, approved, &[], layout)?;
    if plan.empty() {
        return Ok((plan, BTreeSet::new()));
    }
    let live = resolve_on(
        doc,
        plan,
        false,
        None,
        Some(Verification::Read(k)),
        |cfg, iface| samples.remove(iface).unwrap_or_else(|| peer(cfg, iface)),
    )?;
    Ok((live.plan, live.endpoints))
}

enum NativeFullFamilies {
    Dual,
    Ipv4,
}

fn fresh_full_ipv6_reject(k: &super::Kernel<'_>) -> Option<String> {
    if !k.ipv6_stack().ok()? {
        return None;
    }
    let wan = k.legacy_wan(false).ok()?;
    if k.legacy_wan(true).ok()? != wan {
        return None;
    }
    super::handoff::implicit_multi::verify_ipv6(k).ok()?;
    Some(wan)
}

fn witnessed_native_families(
    k: &super::Kernel<'_>,
    cfg: &Value,
    iface: &str,
    boot: &str,
    target: &Target,
    live: &LivePeer,
) -> Option<NativeFullFamilies> {
    let native = live.active_replacement_peer.as_ref()?;
    let expected = cfg["endpoint"]
        .as_str()
        .and_then(|address| address.parse().ok())
        .and_then(super::mtu_edit::canonical_socket);
    let owned = live.nested_mtu.is_none()
        && matches!(live.socket_mark, 0 | nfqws2_awg_profile::DIRECT_SOCKET_MARK)
        && Some(live.endpoint) == expected
        && native.owner.valid()
        && native.owner.id == target.id
        && native.owner.iface == iface
        && native.owner.boot == boot
        && native.owner.nested.is_none()
        && native.fingerprint != [0; 32]
        && native.endpoint == live.endpoint
        && native.socket_mark == live.socket_mark
        && native.mtu >= 1280
        && native.mtu == target.mtu
        && native.underlay.is_none()
        && !native.nested_only;
    let has_default = |default| {
        [&live.allowed, &native.allowed]
            .into_iter()
            .all(|allowed| allowed.iter().any(|prefix| prefix == default))
    };
    if !owned || !has_default("0.0.0.0/0") {
        return None;
    }
    if live.ipv6_reachable && has_default("::/0") {
        return Some(NativeFullFamilies::Dual);
    }
    let ipv4_only = !live.ipv6_reachable
        && live.allowed.iter().chain(&native.allowed).all(|prefix| {
            prefix
                .parse::<Prefix>()
                .is_ok_and(|net| net.family() == Family::V4)
        })
        && k.call(
            "ip",
            &["-6", "addr", "show", "dev", iface, "scope", "global"],
        )
        .is_ok_and(|output| output.trim().is_empty());
    ipv4_only.then_some(NativeFullFamilies::Ipv4)
}

#[cfg(test)]
pub(super) fn compile(
    doc: &Value,
    snapshot: Option<&DnsSnapshot>,
    approved: bool,
) -> io::Result<Plan> {
    compile_with_layout(doc, snapshot, approved, &[], Layout::default())
}
#[cfg(test)]
pub(super) fn compile_with_layout(
    doc: &Value,
    snapshot: Option<&DnsSnapshot>,
    approved: bool,
    members: &[super::learning::Member],
    layout: Layout,
) -> io::Result<Plan> {
    compile_effective(
        doc,
        crate::policy::current(doc)?,
        snapshot,
        approved,
        members,
        layout,
    )
}
pub(super) fn compile_effective(
    doc: &Value,
    mut policy: crate::Routing,
    snapshot: Option<&DnsSnapshot>,
    approved: bool,
    members: &[super::learning::Member],
    mut layout: Layout,
) -> io::Result<Plan> {
    policy.active = false;
    let revision = doc["routing_revision"].as_u64().unwrap_or_default();
    if layout.go_ipv4 && layout.legacy_full.is_none() && policy.mode == "full" && policy.zones.is_empty() {
        if layout.implicit_go_full_revision == Some(revision) {
            let zone = super::handoff::implicit_multi::zone(doc, &policy)
                .ok_or_else(|| err("изменился исходный полный туннель AWG2_MULTI"))?;
            policy.zones.push(zone);
        } else if layout.implicit_go_full_revision.is_some() {
            // An explicitly new revision starts with the native family policy.
            layout.go_ipv4 = false;
        }
    }
    let watchdog = layout.legacy_full.is_some()
        && layout.legacy_revision == Some(revision)
        && policy.go_watchdog_full(doc);
    // Before a DNS-only trial there are no destination addresses to validate
    // against a live peer. Still require an enabled owner or eligible reserve,
    // as the Go multi-policy builder does before starting its DNS learner.
    if !approved && !watchdog && policy.has_explicit_policy() && policy.sni_routing {
        let rows = doc["servers"]
            .as_array()
            .ok_or_else(|| err("нет серверов AWG"))?;
        let enabled = |id: &str| {
            rows.iter().any(|r| {
                let cfg = &r["config"];
                r["id"] == id
                    && cfg["enabled"] == true
                    && cfg["client"]["enabled"] == true
                    && matches!(
                        cfg["routing"]["mode"].as_str(),
                        Some("zones" | "include" | "exclude" | "full")
                    )
            })
        };
        let mut graph = None;
        for z in policy
            .zones
            .iter()
            .filter(|z| z.enabled && !z.waiting_for_connection)
        {
            if enabled(&z.tunnel_id) {
                continue;
            }
            if z.direction() == "tunnel" {
                if graph.is_none() {
                    graph = Some(nfqws2_awg_profile::FailoverGraph::load(doc)?);
                }
                if graph
                    .as_ref()
                    .unwrap()
                    .for_rule(&z.tunnel_id, &z.fallback_tunnel_ids)?
                    .into_iter()
                    .any(&enabled)
                {
                    continue;
                }
            }
            return Err(err(
                "для зоны требуется включённое подключение с маршрутизацией",
            ));
        }
    }
    if !watchdog && snapshot.is_none() && crate::observed::dynamic(&policy) {
        crate::observed::Policy::compile(&policy)?;
    }
    let stamp = crate::sources::Generation::from_policy(doc, &policy)?;
    let mut plan = compile_saved_policy(
        doc,
        policy,
        revision,
        snapshot,
        members,
        approved,
        layout,
    )?;
    plan.local_sources = stamp;
    Ok(plan)
}
#[cfg(test)]
pub(super) fn compile_policy(
    doc: &Value,
    policy: crate::Routing,
    revision: u64,
    snapshot: Option<&DnsSnapshot>,
    members: &[super::learning::Member],
    approved: bool,
) -> io::Result<Plan> {
    compile_saved_policy(
        doc,
        policy,
        revision,
        snapshot,
        members,
        approved,
        Layout::default(),
    )
}
pub(super) fn compile_saved_policy(
    doc: &Value,
    policy: crate::Routing,
    revision: u64,
    snapshot: Option<&DnsSnapshot>,
    members: &[super::learning::Member],
    approved: bool,
    mut layout: Layout,
) -> io::Result<Plan> {
    policy.validate(true)?;
    let go_multi_v6_reject = layout
        .go_multi_v6_reject
        .as_ref()
        .filter(|(old, _)| {
            *old == revision
                && layout.go_ipv4
                && policy.mode == "full"
                && policy.has_explicit_policy()
        })
        .map(|(_, wan)| wan.clone());
    // A proven Go watchdog blanket belongs to that saved revision. New
    // explicit zone intent must also regain native IPv6 after an old
    // IPv4-only/forward-reject generation.
    if layout.legacy_full.is_some()
        && layout.legacy_revision.is_some_and(|old| old != revision)
        && policy.has_explicit_policy()
    {
        layout.legacy_full = None;
        layout.legacy_revision = None;
        layout.legacy_scope = None;
        layout.go_ipv4 = false;
    }
    let scoped_policy = policy
        .zones
        .iter()
        .any(|z| z.enabled && !z.waiting_for_connection && !z.source_ips.is_empty());
    let count = policy
        .zones
        .iter()
        .enumerate()
        .filter(|(_, z)| z.enabled)
        .map(|(idx, z)| {
            let lo = members.partition_point(|m| m.zone < idx);
            let hi = members.partition_point(|m| m.zone <= idx);
            (hi - lo + z.ips.len() + z.domains.len())
                .max(1)
                .saturating_mul(z.source_ips.len().max(1))
        })
        .fold(0usize, usize::saturating_add);
    let threshold = if policy.zones.iter().any(|z| z.enabled && z.only_catch_all()) {
        512
    } else {
        128
    };
    let permanent = doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| r["config"]["client"]["double_tunnel_mode"] == "permanent");
    let wide = layout.force_marked
        || permanent
        || (scoped_policy || policy.killswitch) && (!layout.marks.is_empty() || count > threshold);
    let catch = policy.global_default_zone().filter(|_| !wide);
    let watchdog = layout.legacy_full.is_some()
        && layout.legacy_revision == Some(revision)
        && policy.go_watchdog_full(doc);
    let scoped_learner = watchdog && layout.legacy_scope.as_ref().is_some_and(|scope| scope.learner_wanted());
    if watchdog {
        super::legacy_scope::intent(doc, layout.legacy_scope.as_ref())?;
    }
    if catch.is_some() || watchdog || (policy.mode == "full" && !policy.has_explicit_policy()) {
        if snapshot.is_some()
            || !members.is_empty() && !scoped_learner
            || catch.is_none()
                && (layout.go_ipv4 && layout.legacy_full.is_none()
                    || !watchdog
                        && policy
                            .zones
                            .iter()
                            .any(|z| z.enabled && !z.waiting_for_connection))
            || catch.is_some() && layout.legacy_full.is_some()
        {
            return Err(err(
                "для полного туннеля с зональными исключениями требуется отдельная политика",
            ));
        }
        let rows = doc["servers"]
            .as_array()
            .ok_or_else(|| err("нет списка серверов AWG"))?;
        let id = catch
            .map(|z| z.tunnel_id.as_str())
            .or_else(|| doc["active_id"].as_str())
            .ok_or_else(|| err("выберите подключение полного туннеля"))?;
        let owner = rows
            .iter()
            .find(|r| r["id"] == id)
            .ok_or_else(|| err("нет выбранного подключения"))?;
        if owner["config"]["client"]["standby"] == true {
            return Err(err("основной туннель не может быть standby"));
        }
        // The Go single full policy always retains both unreachable defaults
        // for permanent nesting, even with the user's Kill Switch unchecked.
        let permanent_inner = catch.is_none() && owner["config"]["client"]["double_tunnel_mode"] == "permanent";
        let graph = nfqws2_awg_profile::FailoverGraph::load(doc)?;
        let mut plan = Plan {
            revision,
            go_ipv4: catch.is_some()
                || layout
                    .legacy_full
                    .as_ref()
                    .is_some_and(|state| state != &LegacyFull::Dual),
            go_multi_v6_reject,
            legacy_full: layout.legacy_full.clone(),
            legacy_scope: layout.legacy_scope.clone(),
            learned: if scoped_learner { Some(super::learning::legacy_saved(&policy, members)?) } else { None },
            legacy_probe: matches!(
                layout.legacy_full,
                Some(LegacyFull::Dual | LegacyFull::ForwardReject { .. })
            ),
            killswitch: policy.killswitch || permanent_inner,
            full_endpoints: Some(if layout.legacy_full.is_some() || permanent_inner {
                single_endpoints(doc, id, true)?
            } else {
                configured_endpoints(doc, true)?
            }),
            ..Default::default()
        };
        if catch.is_some() {
            let direct = policy
                .zones
                .iter()
                .filter(|z| z.enabled && !z.waiting_for_connection && z.direction() == "direct");
            for value in direct.flat_map(|z| z.ips.iter().chain(&z.domains)) {
                let net: Prefix = value.parse()?;
                if net.family() == Family::V4 {
                    plan.full_direct.insert(net);
                }
            }
        }
        if let Some(zone) = catch {
            let src = Prefix::compact(prefixes(&zone.source_ips, super::packed::LIMIT)?);
            if !src.iter().any(|p| p.any()) {
                plan.full_sources = src
                    .iter()
                    .copied()
                    .filter(|p| !src.iter().any(|other| other != p && other.covers(*p)))
                    .collect();
            }
        }
        let mut interfaces = Vec::new();
        let ids = if plan.legacy_full.is_some() || permanent_inner {
            vec![id]
        } else {
            graph.for_rule(id, catch.map_or(&[], |z| z.fallback_tunnel_ids.as_slice()))?
        };
        for id in ids {
            let (_, iface, target) = profile(doc, rows, id)?;
            if plan.targets.insert(iface.clone(), target).is_some() {
                return Err(err("у подключений полного туннеля совпадает интерфейс"));
            }
            interfaces.push(iface);
        }
        for family in [Family::V4, Family::V6]
            .into_iter()
            .filter(|f| !plan.go_ipv4 || *f == Family::V4)
        {
            let dest = family.any();
            plan.prefixes.insert(dest, interfaces[0].clone());
            if interfaces.len() > 1 {
                plan.reserves
                    .push((Selector { source: dest, dest }, interfaces[1..].to_vec()));
            }
        }
        plan.validate()?;
        return Ok(plan);
    }
    // A persisted exact-name receipt keeps its resolver across upgrades.
    // A new source-bound rule uses live per-client DNS by default.
    let dynamic = snapshot.is_none() && crate::observed::dynamic(&policy);
    let expected = if dynamic {
        None
    } else {
        dns::exact_request(&policy, revision, doc)?
    };
    let request = snapshot.map(|s| &s.request);
    let original_ipv4 = approved
        && expected.as_ref().zip(request).is_some_and(|(now, old)| {
            old.dual_stack.is_empty()
                && old.ipv6_only.is_empty()
                && now.ipv6_only.is_empty()
                && old.revision == now.revision
                && old.names == now.names
        });
    if expected.as_ref() != request && !original_ipv4 {
        return Err(err(
            "отсутствует полный DNS-снимок текущей ревизии политики",
        ));
    }
    let mut source_hash = None;
    if let Some(snapshot) = snapshot {
        snapshot.validate(revision)?;
    }
    if snapshot.is_some() || dynamic {
        let mut hash = dns::SourceHash::default();
        hash.add(&policy)?;
        source_hash = Some(hash);
    }
    if policy.mode == "off" {
        return Ok(Plan::default());
    }
    if !policy.has_explicit_policy() {
        return Err(err(
            "применение поддерживает только явные зоны IP/CIDR и DNS",
        ));
    }
    let ordered_default = policy
        .zones
        .iter()
        .any(|z| z.enabled && !z.waiting_for_connection && z.only_catch_all());
    let go_ipv4 = layout.go_ipv4 || ordered_default;
    let mut plan = Plan {
        go_ipv4,
        go_multi_v6_reject,
        ordered_default,
        killswitch: policy.killswitch,
        revision,
        ..Default::default()
    };
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов"))?;
    let mut graph = None;
    let mut earlier = BTreeSet::<Selector>::new();
    let mut remaining_members = members;
    let large_static = policy
        .zones
        .iter()
        .filter(|z| z.enabled)
        .map(|z| z.ips.len() + z.domains.iter().filter(|v| crate::model::ipish(v)).count())
        .sum::<usize>()
        > super::packed::OLD_LIMIT;
    let classes = if scoped_policy && wide {
        Some(super::scopes::Scopes::from_policy(&policy, go_ipv4)?)
    } else {
        None
    };
    let global = wide
        || (dynamic || large_static || policy.zones.iter().any(|z| z.source_key.is_some()))
            && !policy.killswitch
            && policy
                .zones
                .iter()
                .filter(|z| z.enabled)
                .all(|z| z.source_ips.is_empty());
    let use_sets = global
        && (layout.packed
            || members.len() > 128
            || policy
                .zones
                .iter()
                .filter(|z| z.enabled)
                .map(|z| z.ips.len() + z.domains.iter().filter(|v| crate::model::ipish(v)).count())
                .sum::<usize>()
                + members.len()
                > 128);
    if ordered_default {
        let endpoints = configured_endpoints(doc, true)?;
        for dest in super::full::excluded_v4().chain(
            endpoints
                .into_iter()
                .filter(IpAddr::is_ipv4)
                .map(Prefix::host),
        ) {
            earlier.insert(Selector {
                source: Family::V4.any(),
                dest,
            });
        }
    } else if use_sets {
        // These destinations precede every Go AWG2_MULTI user rule.
        for net in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "127.0.0.0/8",
        ] {
            earlier.insert(Selector {
                source: Family::V4.any(),
                dest: net.parse()?,
            });
        }
    }
    if let Some(classes) = &classes {
        let base = std::mem::take(&mut earlier);
        for &source in classes.members.keys() {
            for s in base.iter().filter(|s| s.dest.family() == source.family()) {
                earlier.insert(Selector { source, ..*s });
            }
            if earlier.len() > super::packed::LIMIT {
                return Err(err("слишком много зональных исключений"));
            }
        }
    }
    for (index, z) in policy.zones.iter().enumerate().filter(|(_, z)| z.enabled) {
        let mut ipv4;
        let z = if go_ipv4 {
            // Go's multi-policy kernel sets are hash:net family inet.
            // Its wildcard DNS learns A records only. Keep the unmodified
            // user policy in the receipt for identity checking and editing.
            ipv4 = z.clone();
            ipv4.ips
                .retain(|v| !v.contains(':') || crate::model::catch_all(v));
            ipv4.source_ips.retain(|v| !v.contains(':'));
            ipv4.domains
                .retain(|v| !(crate::model::ipish(v) && v.contains(':')));
            if ipv4.domains.is_empty()
                && ipv4.ips.is_empty()
                && (!z.domains.is_empty() || !z.ips.is_empty())
            {
                continue;
            }
            &ipv4
        } else {
            z
        };
        // Go finishes an explicit zone apply/restore on its multi-policy path.
        // That path stops the legacy SNI listener and learns from DNS. A bare
        // '*' or default prefix, however, also routes traffic that never used DNS.
        let families = (!z.domains.is_empty() && source_hash.is_some()).then(|| {
            let (v4, v6) = dns::families(doc, z);
            (v4, v6 && !go_ipv4)
        });
        if dynamic {
            if let (Some(hash), Some(families)) = (&mut source_hash, families) {
                hash.add(&families)?;
            }
        }
        if z.waiting_for_connection || !ordered_default && z.domains.is_empty() && z.ips.is_empty()
        {
            return Err(err(
                "правилу нужны доступный туннель и назначения IP или DNS",
            ));
        }
        let zone_members = if dynamic && (!z.domains.is_empty() || z.dns_catch_all()) {
            let start = remaining_members.partition_point(|m| m.zone < index);
            let rest = &remaining_members[start..];
            let (matched, later) = rest.split_at(rest.partition_point(|m| m.zone == index));
            remaining_members = later;
            matched
        } else {
            &[]
        };
        let pending = match select_zone(
            z,
            snapshot.zip(families),
            zone_members,
            &mut earlier,
            plan.scoped.len(),
            Selection {
                global,
                ordered_default,
                scope: classes.as_ref().and_then(|c| c.by_zone.get(&index)),
            },
        ) {
            Err(e) if e.kind() == io::ErrorKind::FileTooLarge && !wide => {
                // Overlap subtraction and exact DNS snapshots can expand even
                // a short input beyond the plain RPDB budget.
                return compile_saved_policy(
                    doc,
                    policy,
                    revision,
                    snapshot,
                    members,
                    approved,
                    Layout {
                        force_marked: true,
                        ..layout
                    },
                );
            }
            other => other?,
        };
        if pending.is_empty() && (source_hash.is_none() || z.direction() != "tunnel") {
            continue;
        }
        let owner = rows
            .iter()
            .find(|r| r["id"] == z.tunnel_id)
            .ok_or_else(|| err("неизвестный основной туннель"))?;
        if owner["config"]["client"]["standby"] == true {
            return Err(err("основной туннель зоны не может быть standby"));
        }
        let has_reserves = !z.fallback_tunnel_ids.is_empty()
            || owner["config"]["client"]["fallback_tunnel_ids"]
                .as_array()
                .is_some_and(|v| !v.is_empty());
        let candidates = if has_reserves {
            if graph.is_none() {
                graph = Some(nfqws2_awg_profile::FailoverGraph::load(doc)?);
            }
            graph
                .as_ref()
                .unwrap()
                .for_rule(&z.tunnel_id, &z.fallback_tunnel_ids)?
        } else {
            vec![z.tunnel_id.as_str()]
        };
        let mut interfaces = Vec::with_capacity(candidates.len());
        if let Some(hash) = &mut source_hash {
            hash.add(&candidates.len())?;
        }
        for id in candidates {
            let (_, iface, target) = profile(doc, rows, id)?;
            if let Some(hash) = &mut source_hash {
                hash.add(&(&iface, &target))?;
            }
            if pending.is_empty() {
                continue;
            }
            if wide
                && permanent
                && rows.iter().any(|r| {
                    r["id"] == id && r["config"]["client"]["double_tunnel_mode"] == "permanent"
                })
            {
                plan.permanent_fences.insert(iface.clone());
            }
            if let Some(old) = plan.targets.get(&iface) {
                if old != &target {
                    return Err(err("один интерфейс указан у нескольких подключений"));
                }
            } else {
                if plan.targets.len() == MAX_TARGETS {
                    return Err(err("не более 64 туннелей в политике маршрутизации"));
                }
                plan.targets.insert(iface.clone(), target);
            }
            interfaces.push(iface);
        }
        for p in pending {
            if interfaces.len() > 1 {
                plan.reserves.push((p, interfaces[1..].to_vec()));
            }
            plan.scoped.push((p, interfaces[0].clone()));
        }
    }
    plan.scoped.sort();
    plan.reserves.sort_unstable_by_key(|(s, _)| *s);
    // Keep old receipts and the single-table fast path for global policies.
    if !layout.keep_global_scoped && plan.scoped.iter().all(|(s, _)| s.source.any()) {
        plan.prefixes = plan
            .scoped
            .drain(..)
            .map(|(s, iface)| (s.dest, iface))
            .collect();
    }
    plan.packed =
        wide && !plan.targets.is_empty() || use_sets || global && plan.prefixes.len() > 128;
    if wide && plan.targets.is_empty() {
        plan.packed = false;
    }
    if let Some(classes) = classes {
        let used = plan
            .scoped
            .iter()
            .map(|(s, _)| s.source)
            .collect::<BTreeSet<_>>();
        plan.source_ranges = classes
            .members
            .into_iter()
            .filter(|(src, _)| used.contains(src))
            .collect();
    }
    if plan.packed
        && (wide || !layout.marks.is_empty() || plan.prefixes.len() > super::packed::OLD_LIMIT)
    {
        plan.assign_marks(&layout.marks)?;
    }
    if !plan.packed && !plan.scoped.is_empty() && !layout.scoped_slots.is_empty() {
        plan.assign_scoped_slots(layout.scoped_slots)?;
    }
    if dynamic {
        plan.learned = Some(super::learning::Saved::new(
            &policy,
            source_hash.expect("dynamic policy hash").finish(),
            members,
        )?);
    } else if let (Some(source), Some(snapshot)) = (source_hash, snapshot) {
        let mut snapshot = snapshot.clone();
        for ips in snapshot.answers.values_mut() {
            ips.sort_unstable();
            ips.dedup();
        }
        plan.dns = Some(dns::Saved {
            snapshot,
            source_hash: source.finish(),
        });
    }
    if plan.empty() {
        if !earlier.is_empty() {
            return Ok(Plan::default());
        }
        return Err(err("нет активных правил с явными IP/CIDR"));
    }
    plan.validate()?;
    Ok(plan)
}

pub(super) fn has_named_endpoint(doc: &Value) -> bool {
    doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["config"]["enabled"] == true)
        .any(|row| {
            let wire = if row["applied_config"].is_object() {
                &row["applied_config"]
            } else {
                &row["config"]
            };
            wire["endpoint"].as_str().is_some_and(|s| {
                !s.trim().is_empty()
                    && s.trim().parse::<SocketAddr>().is_err()
                    && s.trim().parse::<IpAddr>().is_err()
            })
        })
}
fn configured_endpoints(doc: &Value, resolve_names: bool) -> io::Result<BTreeSet<IpAddr>> {
    endpoints_for(doc, resolve_names, |_| true)
}

pub(super) fn endpoints_for(
    doc: &Value,
    resolve_names: bool,
    include: impl FnMut(&Value) -> bool,
) -> io::Result<BTreeSet<IpAddr>> {
    let mut endpoints = BTreeSet::new();
    visit_endpoints(doc, resolve_names, include, |_, _, ip| { endpoints.insert(ip); })?;
    Ok(endpoints)
}

pub(super) fn visit_endpoints(
    doc: &Value,
    resolve_names: bool,
    include: impl FnMut(&Value) -> bool,
    visit: impl FnMut(&Value, Option<SocketAddr>, IpAddr),
) -> io::Result<()> {
    visit_endpoints_with_edit(doc, resolve_names, None, include, visit)
}

pub(super) fn visit_endpoints_with_edit(
    doc: &Value,
    resolve_names: bool,
    active: Option<&nfqws2_awg_profile::RoutedMtuChange>,
    include: impl FnMut(&Value) -> bool,
    visit: impl FnMut(&Value, Option<SocketAddr>, IpAddr),
) -> io::Result<()> {
    visit_transport_endpoints(doc, resolve_names, (active, None), include, visit)
}

pub(super) fn visit_transport_endpoints(
    doc: &Value,
    resolve_names: bool,
    (active, replacement): (
        Option<&nfqws2_awg_profile::RoutedMtuChange>,
        Option<&super::NamedTransportClaims>,
    ),
    mut include: impl FnMut(&Value) -> bool,
    mut visit: impl FnMut(&Value, Option<SocketAddr>, IpAddr),
) -> io::Result<()> {
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов AWG"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    for row in rows {
        let c = &row["config"];
        if c["enabled"] != true || !include(row) {
            continue;
        }
        let wire = if row["applied_config"].is_object() {
            &row["applied_config"]
        } else {
            c
        };
        let configured = wire["endpoint"]
            .as_str()
            .into_iter()
            .map(|value| (value, true))
            .chain(
                c["client"]["endpoint_backups"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(|value| (value, false)),
            );
        for (raw, primary) in configured {
            let v = raw.trim();
            if v.is_empty() {
                continue;
            }
            if let Ok(socket) = v.parse::<SocketAddr>() {
                visit(row, primary.then_some(socket), socket.ip().to_canonical());
            } else if let Ok(ip) = v.parse::<IpAddr>() {
                visit(row, None, ip.to_canonical());
            } else if let Some(replacement) = replacement {
                for address in replacement.addresses(row, primary, raw)? {
                    visit(row, None, address.ip());
                }
            } else if let Some(pinned) = pending_hostname_addresses(doc, row, primary, raw, active)? {
                for address in pinned {
                    visit(row, None, address.ip().to_canonical());
                }
            } else if resolve_names {
                let addresses = nfqws2_awg_profile::resolve_endpoint_addresses(v, deadline)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            format!("не удалось подтвердить адрес VPN Endpoint: {e}"),
                        )
                    })?;
                for address in addresses {
                    visit(row, None, address.ip().to_canonical());
                }
            }
        }
    }
    Ok(())
}

fn pending_hostname_addresses(
    doc: &Value,
    row: &Value,
    primary: bool,
    raw: &str,
    active: Option<&nfqws2_awg_profile::RoutedMtuChange>,
) -> io::Result<Option<Vec<SocketAddr>>> {
    if !primary {
        return Ok(None);
    }
    let unbound = || err("сохранённое имя endpoint не соответствует ожидающей правке AWG");
    if let Some(edit) = active
        .filter(|saved| row["id"] == saved.id)
        .and_then(|saved| saved.endpoint_edit.as_ref())
        .filter(|edit| edit.has_hostname())
    {
        edit.sockets()?;
        return Ok(Some(edit.pinned_addresses(raw).ok_or_else(unbound)?.to_vec()));
    }
    let staged = nfqws2_awg_profile::pending_routed_mtu(row)?;
    if staged
        .as_ref()
        .and_then(|saved| saved.endpoint_edit.as_ref())
        .is_some_and(|edit| edit.has_hostname())
    {
        return nfqws2_awg_profile::routed_hostname_addresses(doc, row)?
            .map(Some)
            .ok_or_else(unbound);
    }
    Ok(None)
}
impl Plan {
    pub(super) fn reject_active_overlap(
        &self,
        doc: &Value,
        connected: &BTreeSet<String>,
    ) -> io::Result<()> {
        let active = endpoints_for(doc, true, |r| {
            r["id"].as_str().is_some_and(|id| connected.contains(id))
        })?;
        self.check_endpoints(&active)
    }
    pub fn uses_family(&self, family: Family) -> bool {
        if family == Family::V6 && self.legacy_full == Some(LegacyFull::Ipv4Only) {
            return false;
        }
        self.flows().any(|(s, _)| s.dest.family() == family)
            || self
                .learned
                .as_ref()
                .is_some_and(|d| d.members.iter().any(|m| Family::of(m.ip) == family))
            || self.dns.as_ref().is_some_and(|d| {
                d.snapshot
                    .answers
                    .values()
                    .flatten()
                    .any(|ip| Family::of(*ip) == family)
            })
    }
    pub fn overlaps_destination(&self, prefix: Prefix) -> bool {
        self.flows().any(|(s, _)| s.dest.overlaps(prefix))
            || self
                .learned
                .as_ref()
                .is_some_and(|d| d.members.iter().any(|m| prefix.contains(m.ip)))
            || self.dns.as_ref().is_some_and(|d| {
                d.snapshot
                    .answers
                    .values()
                    .flatten()
                    .any(|ip| prefix.contains(*ip))
            })
    }
    pub(super) fn check_endpoints(&self, endpoints: &BTreeSet<IpAddr>) -> io::Result<()> {
        if self
            .flows()
            .any(|(s, _)| endpoints.iter().any(|ip| s.dest.contains(*ip)))
            || self
                .learned
                .as_ref()
                .is_some_and(|d| d.members.iter().any(|m| endpoints.contains(&m.ip)))
            || self.dns.as_ref().is_some_and(|d| {
                d.snapshot
                    .answers
                    .values()
                    .flatten()
                    .any(|ip| endpoints.contains(ip))
            })
        {
            return Err(err("политика включает транспортный адрес VPN"));
        }
        Ok(())
    }
}

/// Revalidate a committed policy independently of any newer, unapplied edits.
pub(super) struct Resolution {
    pub plan: Plan,
    /// Transport addresses that still require the ordinary kernel path guard.
    /// Full policies retain their complete set of throw destinations here.
    pub endpoints: BTreeSet<IpAddr>,
    pub unsafe_previous: Vec<Selector>,
    pub mtu_verified: bool,
    pub predecessor_verified: bool,
}

struct VerifiedPeer {
    allowed: Vec<Prefix>,
    mtu: u16,
    nested: bool,
    prefer_ordinary: bool,
}
pub(super) fn restore(
    doc: &Value,
    intent: &Plan,
    previous: Option<&Plan>,
    kernel: Option<&super::Kernel<'_>>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Resolution> {
    resolve_on(doc, intent.clone(), true, previous, kernel.map(Verification::Read), peer)
}

pub(super) fn restore_with_predecessor(
    doc: &Value,
    intent: &Plan,
    previous: Option<&Plan>,
    kernel: &super::Kernel<'_>,
    predecessor: Option<&super::mtu_edit::Predecessor>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Resolution> {
    resolve_with_mtu_edit(doc, intent.clone(), true, previous, Some(Verification::Read(kernel)),
        predecessor.map_or(EditContext::None, EditContext::Predecessor), peer)
}

#[cfg(test)]
pub(super) fn resolve(
    doc: &Value,
    plan: Plan,
    recovering: bool,
    previous: Option<&Plan>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Resolution> {
    resolve_on(doc, plan, recovering, previous, None, peer)
}

#[derive(Clone, Copy)]
pub(super) enum Verification<'a, 'r> {
    Read(&'a super::Kernel<'r>),
    Refresh(&'a super::Kernel<'r>),
}
pub(super) fn resolve_on(
    doc: &Value,
    plan: Plan,
    recovering: bool,
    previous: Option<&Plan>,
    monitor: Option<Verification<'_, '_>>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Resolution> {
    resolve_with_mtu_edit(doc, plan, recovering, previous, monitor, EditContext::None, peer)
}

pub(super) enum EditContext<'a, 'p> {
    None,
    NamedReplacement(&'a super::NamedTransportClaims),
    Applying(&'a super::mtu_edit::Proof<'p>, &'a mut super::mtu_edit::Prover<'a>),
    Predecessor(&'a super::mtu_edit::Predecessor),
    Rearming(&'a Plan),
    WithdrawnMixed { id: &'a str, endpoint: SocketAddr },
}

pub(super) fn resolve_with_mtu_edit(
    doc: &Value,
    mut plan: Plan,
    recovering: bool,
    previous: Option<&Plan>,
    monitor: Option<Verification<'_, '_>>,
    edit: EditContext<'_, '_>,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Resolution> {
    let named_replacement = match &edit {
        EditContext::NamedReplacement(names) => Some(*names),
        _ => None,
    };
    let (mut mtu_edit, predecessor, rearming, withdrawn) = match edit {
        EditContext::None | EditContext::NamedReplacement(_) => (None, None, None, None),
        EditContext::Applying(proof, prove) => (Some((proof, prove)), None, None, None),
        EditContext::Predecessor(predecessor) => (None, Some(predecessor), None, None),
        EditContext::Rearming(previous) => (None, None, Some(previous), None),
        EditContext::WithdrawnMixed { id, endpoint } => (None, None, None, Some((id, endpoint))),
    };
    let dual_edit = mtu_edit.as_ref().is_some_and(|(edit, _)| edit.full.is_some_and(|full| full.dual));
    let hold_ipv6_fence = mtu_edit.as_ref().is_some_and(|(edit, _)| {
        edit.full.is_some_and(|full| full.keep_ipv6_fenced)
    });
    let forwarding = plan.flows().next().is_some();
    let permanent_inner = plan.permanent_full_inner(doc);
    let (mut endpoints, claims) = if plan.legacy_full.is_some() || permanent_inner.is_some() {
        let inner = plan.prefixes.get(&Family::V4.any()).and_then(|i| plan.targets.get(i))
            .ok_or_else(|| err("нет основного полного туннеля"))?;
        (single_endpoints(doc, &inner.id, forwarding)?, super::transport_claims::Claims::default())
    } else {
        let active = mtu_edit.as_ref().map(|(proof, _)| proof.change);
        let claims = super::transport_claims::Claims::read_with_names(
            doc, &plan, forwarding, (active, named_replacement)
        )?;
        (claims.addresses(), claims)
    };
    let permanent_primaries = super::nested_endpoint::permanent_primaries(doc, &plan);
    plan.socket_bypass.clear();
    if plan.go_ipv4 && plan.packed {
        let ordinary = endpoints_for(doc, forwarding, |r| {
            r["config"]["client"]["standby"] != true || r["config"]["client"]["enabled"] != true
        })?;
        plan.socket_bypass = endpoints
            .difference(&ordinary)
            .copied()
            .filter(|ip| ip.is_ipv4() && plan.has_host(*ip))
            .collect();
    }
    if !forwarding {
        plan.check_endpoints(&endpoints)?;
        return Ok(Resolution {
            plan,
            endpoints: BTreeSet::new(),
            unsafe_previous: Vec::new(),
            mtu_verified: false,
            predecessor_verified: false,
        });
    }
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов"))?;
    let mut verified = BTreeMap::new();
    let mut mss = BTreeMap::new();
    let mut unprotected = false;
    let mut reachable = false;
    let mut fresh_probe = None;
    let mut ordinary_live = BTreeSet::new();
    let mut outer_endpoints = BTreeSet::new();
    let mut dormant_primaries = BTreeSet::new();
    for (iface, saved) in &plan.targets {
        let edit = mtu_edit.as_mut().filter(|(edit, _)| edit.change.iface == *iface);
        let retained = predecessor.filter(|held| held.change.iface == *iface && held.change.id == saved.id);
        let checked = (|| {
            let row = rows
                .iter()
                .find(|r| r["id"] == saved.id)
                .ok_or_else(|| err("профиль туннеля удалён"))?;
            if row["config"]["enabled"] != true || row["config"]["client"]["enabled"] != true {
                return Err(err("клиент AWG выключен"));
            }
            let (wire, live_iface, target) = profile(doc, rows, &saved.id)?;
            let paused = || err("сохранённая правка MTU AWG ожидает подтверждения");
            let mut expected = saved.clone();
            if let Some((edit, _)) = &edit {
                let Some(wanted) = edit.wanted else {
                    // A live socket can still use one of the saved answers while
                    // its successor is pending. Observe its claim without granting routes.
                    if edit.parked_named_primary.is_some() && &live_iface == iface && target == expected {
                        if let Ok(live) = peer(wire, iface) {
                            ordinary_live.insert(live.endpoint.ip().to_canonical());
                            outer_endpoints.extend(live.nested_transport.and_then(|witness| {
                                super::mtu_edit::canonical_socket(witness.outer_endpoint)
                                    .map(|endpoint| endpoint.ip())
                            }));
                        }
                    }
                    return Err(paused());
                };
                expected.mtu = wanted;
            } else if let Some(pending) = nfqws2_awg_profile::pending_routed_mtu(row)? {
                if retained.is_none_or(|held| held.change != pending) {
                    return Err(paused());
                }
            }
            if &live_iface != iface || target != expected {
                return Err(err(
                    "идентичность или параметры сохранённого туннеля изменились",
                ));
            }
            let live = peer(wire, iface)?;
            let nested = live.socket_mark >> 28 == 0xa;
            let primary = permanent_primaries.get(iface);
            let sole_primary = primary.is_some_and(|primary| {
                claims.sole_primary(&saved.id, primary.endpoint)
            });
            if let Some(outer) = live
                .nested_transport
                .as_ref()
                .and_then(|witness| super::mtu_edit::canonical_socket(witness.outer_endpoint))
            {
                outer_endpoints.insert(outer.ip());
            }
            // A sealed old port/address can remain active through its marked
            // outer while the new owner is pending. Keep the payload fenced
            // without mistaking that exact nested socket for a WAN claimant.
            let retiring_nested = edit.as_ref().is_some_and(|(edit, _)| {
                let Some(Verification::Read(k) | Verification::Refresh(k)) = monitor else {
                    return false;
                };
                edit.verified_retiring_nested_path(k, &live)
            });
            let sole_live_nested_primary = nested
                && primary.is_some_and(|primary| {
                    sole_primary
                        && super::mtu_edit::canonical_socket(live.endpoint) == Some(primary.endpoint)
                });
            if !retiring_nested && !sole_live_nested_primary {
                let ip = live.endpoint.ip().to_canonical();
                ordinary_live.insert(ip);
                if !permanent_primaries.is_empty() {
                    endpoints.insert(ip);
                }
            }
            if let Some(held) = retained {
                held.verify(&live, iface, expected.mtu)?;
            }
            let editing = edit.is_some();
            let staged_dormant = edit.as_ref().and_then(|(edit, _)| edit.dormant_primary);
            let permanent_mtu = if let Some(primary) = primary {
                let (Verification::Read(k) | Verification::Refresh(k)) = monitor.ok_or_else(paused)?;
                Some(primary.verify(k, row, iface, &live, expected.mtu, !sole_primary)?)
            } else {
                None
            };
            let active_mtu = if let Some((edit, prove)) = edit {
                let (Verification::Read(k) | Verification::Refresh(k)) = monitor.ok_or_else(paused)?;
                let mtu = edit.effective_mtu(k, &live, *prove)?;
                if edit.full.is_some() {
                    super::mtu_edit::FullEdit::verify_legacy_transport(k, &plan, &live)?;
                }
                if dual_edit {
                    fresh_probe = live.fresh_bound_ipv6_probe;
                }
                if permanent_mtu.is_some_and(|actual| actual != mtu) {
                    return Err(paused());
                }
                mtu
            } else {
                permanent_mtu.or(live.nested_mtu).unwrap_or(expected.mtu)
            };
            let dormant = if editing {
                staged_dormant
            } else if super::transport_claims::explicit(&plan) {
                super::transport_claims::dormant_direct_primary(row, iface, &live, expected.mtu)
            } else {
                None
            };
            // A recent handshake on the primary's former direct incarnation
            // is insufficient when client policy already requires its outer.
            if permanent_inner.as_deref() == Some(iface) && (!editing || !nested) {
                let outer = &row["config"]["client"]["double_tunnel_id"];
                let waiting = || err("постоянный полный туннель ожидает выбранного внешнего транспорта");
                let outer_id = outer.as_str().filter(|id| !id.is_empty()).ok_or_else(waiting)?;
                if !rows.iter().any(|r|
                    r["id"] == outer_id && r["config"]["enabled"] == true && r["config"]["client"]["enabled"] == true
                ) {return Err(waiting());}
                let (_, outer_iface, _) = profile(doc, rows, outer_id)?;
                let (Verification::Read(k) | Verification::Refresh(k)) = monitor.ok_or_else(waiting)?;
                verify_nested_path(k, iface, &outer_iface, &live)?;
            }
            reachable = live.ipv6_reachable;
            if plan
                .socket_bypass
                .contains(&live.endpoint.ip().to_canonical())
                && live.socket_mark != nfqws2_awg_profile::DIRECT_SOCKET_MARK
                && live.socket_mark >> 28 != 0xa
            {
                unprotected = true;
            }
            let prefer_ordinary = nested
                && live.prefer_ordinary
                && row["config"]["client"]["double_tunnel_mode"] == "automatic";
            let nets = grants(live, &mut endpoints)?;
            if editing && plan.flows().any(|(selector, primary)| {
                (primary == iface || plan.reserves_for(selector).contains(iface)) &&
                    if (dual_edit || hold_ipv6_fence) && selector.dest.family() == Family::V6 {
                        false
                    } else if selector.dest.family() == Family::V6 && active_mtu < 1280 {
                        // The nested transport can be ready for IPv4 while its
                        // IPv6 selectors stay on their configured guard/reserve.
                        !nested
                    } else {
                        !nets.iter().any(|network| network.covers(selector.dest))
                    }
            }) {
                return Err(paused());
            }
            if plan.firewall == Backend::Legacy {
                let ceiling = active_mtu.checked_sub(40)
                    .filter(|n| (536..=8960).contains(n))
                    .ok_or_else(|| err("неверный действующий MTU туннеля AWG"))?;
                mss.insert(iface.clone(), ceiling);
            }
            if let Some(primary) = dormant.filter(|endpoint| claims.sole_primary(&saved.id, *endpoint)) {
                dormant_primaries.insert(primary.ip());
            }
            Ok(VerifiedPeer { allowed: nets, mtu: active_mtu, nested, prefer_ordinary })
        })();
        verified.insert(iface.clone(), checked);
    }
    if let Some(Verification::Read(k) | Verification::Refresh(k)) = monitor {
        for ip in permanent_primaries.values().map(|primary| primary.endpoint.ip()) {
            if outer_endpoints.contains(&ip) {
                super::nested_endpoint::require_independent_wan(k, ip)?;
            }
        }
    }
    ordinary_live.extend(outer_endpoints);
    let unselected_permanent = if mtu_edit.is_none()
        && predecessor.is_none()
        && permanent_primaries
            .keys()
            .any(|iface| verified[iface].is_ok())
    {
        match monitor {
            Some(Verification::Read(k) | Verification::Refresh(k)) => {
                super::nested_endpoint::unselected_permanent_transports(
                    k, doc, &plan, &claims, &mut peer,
                )
            }
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    for (_, outer) in &unselected_permanent {
        ordinary_live.insert(*outer);
        endpoints.insert(*outer);
    }
    let mtu_edit = mtu_edit.map(|(edit, _)| edit);
    let peer_verified = mtu_edit.is_some_and(|edit| verified.get(&edit.change.iface).is_some_and(Result::is_ok));
    // An owned IPv4 peer can bring up the bound control route while the IPv6
    // payload is still fenced. Only an observation of that phase can settle.
    let mut dual_settled = !dual_edit;
    if let Some(edit) = mtu_edit.filter(|_| dual_edit && peer_verified) {
        let iface = &edit.change.iface;
        let (Verification::Read(k) | Verification::Refresh(k)) = monitor.ok_or_else(|| err("нет проверяемого IPv6-маршрута AWG"))?;
        if previous.is_some_and(|old| super::mtu_edit::dual_probe_phase(old, iface))
            && k.verify_probe_iface(iface).is_ok()
        {
            let v6 = Family::V6.any();
            let peer = verified[iface].as_ref().unwrap();
            let capable = peer.mtu >= 1280 && peer.allowed.contains(&v6)
                && k.call("ip", &["-6", "addr", "show", "dev", iface, "scope", "global"])?
                    .split_ascii_whitespace().any(|word| word == "inet6");
            if fresh_probe == Some(false) || !capable {
                let wan = super::mtu_edit::legacy_dual_reject_wan(k, iface)?;
                plan.legacy_full = Some(LegacyFull::ForwardReject { wan, ipv6_endpoint: false });
                plan.go_ipv4 = true;
                plan.prefixes.remove(&v6);
                dual_settled = true;
            } else if fresh_probe == Some(true) {
                dual_settled = true;
            }
        }
    }
    let mtu_verified = peer_verified && dual_settled;
    let predecessor_verified = predecessor.is_some_and(|held| verified.get(&held.change.iface).is_some_and(Result::is_ok));
    if let Some(edit) = mtu_edit.filter(|_| mtu_verified) {
        plan.targets.get_mut(&edit.change.iface).unwrap().mtu = edit.wanted.unwrap();
    }
    plan.mss = mss;
    // Only the ordinary watchdog may change the IPv6 mode established by a
    // completed Go handoff. Apply and commit prove exactly the sampled state.
    let editing_full = mtu_edit.is_some_and(|edit| edit.full.is_some());
    if let Some(Verification::Refresh(k)) = monitor.filter(|_| editing_full) {
        super::mtu_edit::FullEdit::verify_legacy_guard(k, &plan)?;
    }
    if let Some(Verification::Refresh(k)) = monitor.filter(|_| !editing_full && plan.legacy_full.is_some()) {
        let v4 = Family::V4.any();
        let v6 = Family::V6.any();
        let iface = plan
            .prefixes
            .get(&v4)
            .ok_or_else(|| err("нет основного IPv4 маршрута Go"))?;
        let target = &plan.targets[iface];
        let cfg = &rows
            .iter()
            .find(|r| r["id"] == target.id)
            .ok_or_else(|| err("профиль туннеля удалён"))?["config"];
        let state = if !k.ipv6_stack()? {
            LegacyFull::Ipv4Only
        } else {
            let permanent = cfg["client"]["double_tunnel_mode"] == "permanent";
            let coverage = target.mtu >= 1280
                && verified
                    .get(iface.as_str())
                    .and_then(|r| r.as_ref().ok())
                    .is_some_and(|peer| peer.mtu >= 1280 && peer.allowed.contains(&v6));
            if permanent
                || coverage
                    && reachable
                    && k.call(
                        "ip",
                        &["-6", "addr", "show", "dev", iface, "scope", "global"],
                    )?
                    .split_ascii_whitespace()
                    .any(|w| w == "inet6")
            {
                LegacyFull::Dual
            } else {
                let ipv6_endpoint = LegacyFull::ipv6_endpoint(cfg)?;
                LegacyFull::ForwardReject {
                    wan: k.legacy_wan(ipv6_endpoint)?,
                    ipv6_endpoint,
                }
            }
        };
        plan.go_ipv4 = state != LegacyFull::Dual;
        if plan.go_ipv4 {
            plan.prefixes.remove(&v6);
        } else {
            plan.prefixes.insert(v6, iface.clone());
        }
        plan.legacy_probe = state != LegacyFull::Ipv4Only;
        if let Some(scope) = &mut plan.legacy_scope {
            scope.refresh(k, state != LegacyFull::Ipv4Only)?;
        }
        plan.legacy_full = Some(state);
    }
    if let Some(scope) = &mut plan.legacy_scope {
        let learned = plan.learned.as_ref().map_or(&[][..], |saved| &saved.members);
        let grant = plan
            .prefixes
            .get(&Family::V4.any())
            .and_then(|i| verified.get(i.as_str()))
            .and_then(|p| p.as_ref().ok());
        scope.tunnel_route = matches!(plan.legacy_full, Some(LegacyFull::ForwardReject { .. }))
            && scope.needs_tunnel()
            && grant.is_some_and(|peer| {
                scope.tunnel_covered(learned, |prefix| prefix.ancestors().any(|n| peer.allowed.contains(&n)))
            });
    }
    if unprotected {
        return Err(err(
            "действующий резервный туннель не подтвердил отдельный маршрут своего сокета",
        ));
    }
    let eligible = |iface: &str, dest: Prefix| {
        if dest.family() == Family::V6
            && (hold_ipv6_fence || !dual_settled || plan.targets[iface].mtu < 1280)
        {
            return false;
        }
        verified
            .get(iface)
            .and_then(|v| v.as_ref().ok())
            .is_some_and(|peer| {
                (dest.family() != Family::V6 || peer.mtu >= 1280)
                    && peer.allowed.iter().any(|n| n.covers(dest))
            })
    };
    let mut unsafe_previous = Vec::new();
    if let Some(old) = previous {
        for (s, primary) in old.flows() {
            if old
                .effective(s, primary)
                .is_some_and(|i| old.targets.get(i) != plan.targets.get(i) || !eligible(i, s.dest))
            {
                unsafe_previous.push(s);
            }
        }
    }
    let mut selected = Vec::new();
    for (s, primary) in plan.flows() {
        let primary_ready = eligible(primary, s.dest);
        if primary_ready && !verified[primary].as_ref().is_ok_and(|p| p.prefer_ordinary) {
            continue;
        }
        let permanent_primary = permanent_primaries.contains_key(primary);
        let waiting_for_predecessor = recovering && predecessor.is_some_and(|held| held.change.iface == primary);
        let previous_choice = previous.and_then(|old| old.effective(s, primary));
        let reserve = plan.reserves_for(s).iter().find(|i| !permanent_primary
            && (!waiting_for_predecessor || previous_choice == Some(i.as_str()))
            && eligible(i, s.dest));
        if primary_ready && reserve.is_none() {
            continue;
        }
        let full_outage = plan.full_endpoints.is_some()
            && (recovering || permanent_inner.is_some() || s.dest.family() == Family::V6);
        let nested_ipv4_only = recovering && s.dest.family() == Family::V6
            && verified[primary].as_ref().is_ok_and(|peer| peer.nested && peer.mtu < 1280);
        let waiting_for_outer = recovering && permanent_primary;
        let waiting_for_rearm = rearming.is_some_and(|prior| {
            !prior.targets.contains_key(primary) || prior.effective(s, primary).is_none()
        });
        if !full_outage
            && !waiting_for_rearm
            && reserve.is_none()
            && !nested_ipv4_only
            && !waiting_for_outer
            && !waiting_for_predecessor
            && !mtu_edit.is_some_and(|edit| edit.change.iface == primary)
            && (!recovering || (!plan.protected(primary) && plan.reserves.is_empty()))
        {
            return Err(err(format!(
                "{}: {}",
                primary,
                verified[primary].as_ref().err().map_or_else(
                    || "нет действующего пира с подходящими AllowedIPs".into(),
                    ToString::to_string
                )
            )));
        }
        selected.push((s, reserve.cloned()));
    }
    selected.sort_unstable_by_key(|(s, _)| *s);
    plan.selected = selected;
    plan.offline.clear();
    if let Some((edit, primary)) = mtu_edit.and_then(|edit| edit.parked_dormant_primary.map(|primary| (edit, primary))) {
        // A pending reserve can leave this target fenced before its first handshake.
        // Keep the dormant primary guarded whenever any live or independent claim needs it.
        if claims.sole_primary(&edit.change.id, primary)
            && !plan.flows().any(|(selector, owner)| plan.effective(selector, owner) == Some(edit.change.iface.as_str()))
        {
            dormant_primaries.insert(primary.ip());
        }
    }
    if let Some((edit, full)) = mtu_edit.and_then(|edit| edit.full.map(|full| (edit, full))) {
        let mut retained = full.retained(&plan, previous)?;
        if mtu_verified {
            full.retire(&mut retained, &endpoints, edit.forward);
        }
        endpoints = retained;
    }
    if let Some(saved) = plan.full_endpoints.as_mut() {
        saved.clone_from(&endpoints);
        plan.validate()?;
    } else {
        plan.check_endpoints(&endpoints.difference(&plan.socket_bypass).copied().collect())?;
        endpoints.retain(|ip| !dormant_primaries.contains(ip) || ordinary_live.contains(ip));
        if let Some((id, endpoint)) = withdrawn {
            if claims.sole_primary(id, endpoint) && !ordinary_live.contains(&endpoint.ip()) {
                endpoints.remove(&endpoint.ip());
            }
        }
        if let Some(held) = predecessor {
            endpoints.retain(|ip| {
                !held.future.contains(ip) || !claims.solely_owned_by(*ip, &held.change.id)
                    || ordinary_live.contains(ip)
            });
        }
        // Collision checking above keeps all DNS answers. Only the exact live
        // tuple and independently claimed addresses need ordinary WAN here.
        if let Some((owner, pins, selected)) = mtu_edit.and_then(|proof| {
            let edit = proof.change.endpoint_edit.as_ref()?;
            if mtu_verified {
                let raw = if proof.forward { &edit.after } else { &edit.before };
                return edit
                    .pinned_addresses(raw)
                    .map(|pins| (&proof.change.id, pins, None));
            }
            let selected = proof.parked_named_primary?;
            // Reinstall confirmed fences before the selected peer can authenticate.
            let parked = !plan.flows().any(|(selector, owner)| {
                plan.effective(selector, owner) == Some(proof.change.iface.as_str())
            });
            parked.then_some((
                &proof.change.id,
                edit.resolved_after.as_slice(),
                Some(selected),
            ))
        }) {
            for address in pins {
                let ip = address.ip();
                if selected != Some(ip)
                    && claims.sole_claim_by(ip, owner)
                    && !ordinary_live.contains(&ip)
                {
                    endpoints.remove(&ip);
                }
            }
        }
        for (iface, primary) in permanent_primaries {
            let ip = primary.endpoint.ip();
            if claims.sole_primary(&plan.targets[&iface].id, primary.endpoint)
                && !ordinary_live.contains(&ip) && (verified[&iface].is_ok() || !plan.flows().any(|(selector, owner)| {
                plan.effective(selector, owner) == Some(iface.as_str())
            })) {
                endpoints.remove(&ip);
            }
        }
        for (ip, _) in unselected_permanent {
            if !ordinary_live.contains(&ip) {
                endpoints.remove(&ip);
            }
        }
        if !plan.marks.is_empty() {
            super::marked::check_size(&plan)?;
        }
    }
    Ok(Resolution {
        plan,
        endpoints,
        unsafe_previous,
        mtu_verified,
        predecessor_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn all_subnets_of_two_eight_address_ranges_match_the_first_rule() {
        fn nets(base: u32) -> Vec<Prefix> {
            (29..=32)
                .flat_map(|bits| {
                    (0..8).step_by(1 << (32 - bits)).map(move |offset| {
                        format!("{}/{bits}", Ipv4Addr::from(base + offset))
                            .parse()
                            .unwrap()
                    })
                })
                .collect()
        }
        let source = u32::from(Ipv4Addr::new(192, 168, 1, 0));
        let dest = u32::from(Ipv4Addr::new(203, 0, 113, 0));
        let sources = nets(source);
        let dests = nets(dest);
        let bitmap = |scope: Selector| {
            let mut mask = 0u64;
            for s in 0..8 {
                for d in 0..8 {
                    if scope.source.contains(Ipv4Addr::from(source + s).into())
                        && scope.dest.contains(Ipv4Addr::from(dest + d).into())
                    {
                        mask |= 1 << (s * 8 + d);
                    }
                }
            }
            mask
        };
        let mut selectors = BTreeMap::new();
        for src in sources {
            for &dst in &dests {
                let s = Selector {
                    source: src,
                    dest: dst,
                };
                selectors.insert(s, bitmap(s));
            }
        }
        let mut remaining = Vec::new();
        for (&candidate, &all) in &selectors {
            for (&first, &matched) in &selectors {
                candidate.excluding(first, &mut remaining);
                let mut union = 0;
                for s in remaining.drain(..) {
                    let covered = selectors[&s];
                    assert_eq!(union & covered, 0, "overlapping output {s:?}");
                    union |= covered;
                }
                assert_eq!(union, all & !matched);
            }
        }
    }
}
