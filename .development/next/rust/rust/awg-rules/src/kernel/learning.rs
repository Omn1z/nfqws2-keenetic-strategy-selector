//! Destinations confirmed by the router's own DNS server. Preserve the
//! applied rule order even while the user edits a different draft.
use super::{boot_id, dns, err, kernel, objects, plan, transition, Journal, LivePeer};
use crate::{observed::Policy, Routing};
use base64ct::{Base64, Encoding};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use nfqws2_router_command::Runner;
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{self, Read, Write},
    net::IpAddr,
    sync::{Arc, LazyLock},
};

const MAX_MEMBERS: usize = super::packed::LIMIT;
const MAX_POLICY: usize = 24 << 20;
const MAX_ENCODED: usize = 8 << 20;
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub(super) struct Member {
    pub zone: usize,
    pub ip: IpAddr,
    pub until: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    policy: Arc<str>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    source_keys: std::collections::BTreeMap<usize, String>,
    pub hash: String,
    #[serde(deserialize_with = "super::journal::route_rows")]
    pub members: Vec<Member>,
}
impl Saved {
    pub fn new(policy: &Routing, hash: String, members: &[Member]) -> io::Result<Self> {
        let raw = serde_json::to_string(policy)?;
        if raw.len() > MAX_POLICY {
            return Err(err("настройки динамических зон превышают 24 МиБ"));
        }
        let raw = if raw.len() > 32 * 1024 {
            let mut compressor = ZlibEncoder::new(Vec::new(), Compression::fast());
            compressor.write_all(raw.as_bytes())?;
            format!("zlib:{}", Base64::encode_string(&compressor.finish()?))
        } else {
            raw
        };
        let saved = Self {
            source_keys: policy
                .zones
                .iter()
                .enumerate()
                .filter_map(|(i, z)| Some((i, z.source_key.clone()?)))
                .collect(),
            policy: raw.into(),
            hash,
            members: members.to_owned(),
        };
        saved.validate()?;
        Ok(saved)
    }
    pub fn validate(&self) -> io::Result<()> {
        if self.policy.len() > MAX_ENCODED
            || self.source_keys.iter().any(|(i, key)| {
                *i >= 2048 || key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit())
            })
            || self.policy.bytes().any(|b| b < b' ')
            || self.hash.len() != 64
            || !self.hash.bytes().all(|b| b.is_ascii_hexdigit())
            || self.members.len() > MAX_MEMBERS
            || self
                .members
                .chunk_by(|a, b| a.zone == b.zone)
                .any(|zone| zone.len() > super::packed::ZONE_LIMIT)
            || self
                .members
                .iter()
                .any(|m| m.zone >= 2048 || !plan::Prefix::host(m.ip).safe())
            || self
                .members
                .windows(2)
                .any(|m| (m[0].zone, m[0].ip) >= (m[1].zone, m[1].ip))
        {
            return Err(err("повреждён снимок маршрутизации по DNS-ответам"));
        }
        Ok(())
    }
    pub fn routing(&self) -> io::Result<Routing> {
        let mut policy: Routing = if let Some(encoded) = self.policy.strip_prefix("zlib:") {
            let compressed =
                Base64::decode_vec(encoded).map_err(|_| err("повреждён сжатый снимок зон"))?;
            let mut reader = ZlibDecoder::new(&compressed[..]).take(MAX_POLICY as u64 + 1);
            let policy = serde_json::from_reader(&mut reader)?;
            if reader.limit() == 0 {
                return Err(err("слишком большой снимок зон"));
            }
            policy
        } else {
            serde_json::from_str(&self.policy)?
        };
        for (index, key) in &self.source_keys {
            let zone = policy
                .zones
                .get_mut(*index)
                .ok_or_else(|| err("неизвестная зона локального списка"))?;
            zone.source_key = Some(key.clone());
        }
        Ok(policy)
    }
}

pub(super) fn legacy_policy(db: &Store, doc: &Value) -> io::Result<Routing> {
    let mut policy = super::legacy_scope::owner(doc)?;
    policy.active = false;
    policy.trace_enabled = false;
    let owner = doc["active_id"].as_str().unwrap_or_default();
    for zone in &mut policy.zones {
        let id = zone.tunnel_id.trim();
        zone.tunnel_id = if id.is_empty() && !zone.waiting_for_connection {
            owner.to_owned()
        } else {
            id.to_owned()
        };
    }
    crate::sources::expand(db, policy)
}

pub(super) fn legacy_saved(policy: &Routing, members: &[Member]) -> io::Result<Saved> {
    // Validate the actual name classifier before taking ownership of Go's
    // packet path. This preserves its raw zone indices in the saved policy.
    Policy::compile_legacy_full(policy)?;
    let mut hash = dns::SourceHash::default();
    hash.add(policy)?;
    Saved::new(policy, hash.finish(), members)
}

pub struct Observation {
    pub policy: Policy,
    pub revision: u64,
    pub ready: bool,
    pub trial_expires: u64,
    pub block_aaaa: Vec<usize>,
    pub go_ipv4: bool,
}
impl Observation {
    /// Only a listener bound to the witnessed LAN may use a legacy scoped
    /// client's address. Other transports can still use the global policy.
    pub fn legacy_accepts_peer(&self, client: IpAddr, ingress: Option<&str>) -> bool {
        self.policy.legacy_accepts_peer(client, ingress)
    }
}
pub fn observation(db: &Store) -> io::Result<Option<Observation>> {
    observation_from_journal(db, &Journal::read(db)?)
}
pub(super) fn observation_from_journal(db: &Store, j: &Journal) -> io::Result<Option<Observation>> {
    let installed = j.installed.learned.is_some();
    let p = if installed {
        &j.installed
    } else {
        &j.committed
    };
    let Some(saved) = &p.learned else {
        return Ok(None);
    };
    let routing = saved.routing()?;
    let ready = installed
        && j.preparing.is_empty()
        && (j.expires == 0 || nfqws2_awg_profile::now() < j.expires)
        && !super::active_replacement::pending_dns_settlement(db)?;
    let mut block_aaaa = Vec::new();
    let legacy_full = p.legacy_full.is_some();
    let scope = if legacy_full {
        legacy_classifier(p, &routing)?
    } else {
        Policy::compile(&routing)?
    };
    if ready {
        let doc = (!p.go_ipv4 && !legacy_full)
            .then(|| nfqws2_awg_profile::read(db))
            .transpose()?;
        for (zone, rule) in routing.zones.iter().enumerate() {
            if rule.enabled
                && !rule.waiting_for_connection
                && (legacy_full || !rule.domains.is_empty() || rule.dns_catch_all())
                && rule.direction() == "tunnel"
                && if legacy_full {
                    p.legacy_full != Some(plan::LegacyFull::Dual)
                } else {
                    doc.as_ref().is_none_or(|doc| !dns::families(doc, rule).1)
                }
            {
                block_aaaa.push(zone);
            }
        }
    }
    Ok(Some(Observation {
        policy: scope,
        revision: p.revision,
        trial_expires: j.expires,
        ready,
        block_aaaa,
        go_ipv4: p.go_ipv4,
    }))
}

static SHARED_CDN: LazyLock<Vec<plan::Prefix>> = LazyLock::new(|| {
    // Same protected shared edges as the Go LAN-wide direct exception.
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 8.47.69.0/24 8.6.112.0/24 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"
        .split_ascii_whitespace().map(|s|s.parse().expect("constant CDN prefix")).collect()
});

pub(crate) fn shared_cdn_address(ip: IpAddr) -> bool {
    SHARED_CDN.iter().any(|net| net.contains(ip))
}

pub struct Answer<'a> {
    pub revision: u64,
    pub zone: usize,
    pub addresses: &'a [IpAddr],
    pub ttl: u32,
    pub qtype: u16,
}

pub struct ArchiveAnswer<'a> {
    pub revision: u64,
    pub name: &'a str,
    pub addresses: &'a [IpAddr],
    pub ttl: u32,
    pub qtype: u16,
}

enum Learn<'a> {
    Client(Answer<'a>, DnsOrigin<'a>, Option<&'a str>),
    Archive(ArchiveAnswer<'a>),
}

pub struct Applied {
    pub suppress: bool,
    pub accepted: Vec<IpAddr>,
}

#[derive(Clone, Copy)]
pub struct DnsOrigin<'a> {
    pub client: Option<IpAddr>,
    /// The interface of a device-bound DNS listener, never DNS metadata.
    pub ingress: Option<&'a str>,
}

/// Verify the complete address set before the DNS reply reaches the client.
pub fn learn_answer(
    db: &Store,
    run: &dyn Runner,
    answer: Answer<'_>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    before_change: impl FnOnce() -> io::Result<()>,
) -> io::Result<Applied> {
    learn_client_answer(db, run, answer, None, peer, before_change)
}
pub fn learn_client_answer(
    db: &Store,
    run: &dyn Runner,
    answer: Answer<'_>,
    client: Option<IpAddr>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    before_change: impl FnOnce() -> io::Result<()>,
) -> io::Result<Applied> {
    let origin = DnsOrigin {
        client,
        ingress: None,
    };
    learn(
        db,
        run,
        Learn::Client(answer, origin, None),
        peer,
        before_change,
    )
}

/// The old full watchdog learns the same validated destination for every
/// matching per-client set, even when another rule wins name tracing.
pub fn learn_named_client_answer(
    db: &Store,
    run: &dyn Runner,
    answer: Answer<'_>,
    origin: DnsOrigin<'_>,
    name: &str,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    before_change: impl FnOnce() -> io::Result<()>,
) -> io::Result<Applied> {
    learn(
        db,
        run,
        Learn::Client(answer, origin, Some(name)),
        peer,
        before_change,
    )
}

/// The fresh reply offers destinations to the current named rules. The saved
/// policy supplies all source selectors, keeping observations out of this path.
pub fn learn_archived_answer(
    db: &Store,
    run: &dyn Runner,
    answer: ArchiveAnswer<'_>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    before_change: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    learn(db, run, Learn::Archive(answer), peer, before_change).map(|_| ())
}

fn remember(
    members: &mut Vec<Member>,
    zone: usize,
    ip: IpAddr,
    until: u64,
    padding: u64,
) -> io::Result<()> {
    match members.binary_search_by_key(&(zone, ip), |m| (m.zone, m.ip)) {
        Ok(i) if members[i].until >= until => (),
        Ok(i) => members[i].until = until.saturating_add(padding),
        Err(i) => {
            let start = members.partition_point(|v| v.zone < zone);
            let end = members.partition_point(|v| v.zone <= zone);
            if members.len() >= MAX_MEMBERS || end - start >= super::packed::ZONE_LIMIT {
                return Err(err("достигнут предел действующих адресов динамических зон"));
            }
            members.insert(
                i,
                Member {
                    zone,
                    ip,
                    until: until.saturating_add(padding),
                },
            );
        }
    }
    Ok(())
}

fn legacy_candidate(plan: &plan::Plan, members: Vec<Member>) -> io::Result<plan::Plan> {
    let mut candidate = plan.clone();
    candidate.offline.clear();
    candidate.selected.clear();
    candidate
        .learned
        .as_mut()
        .ok_or_else(|| err("DNS-политика снята"))?
        .members = members;
    candidate.validate()?;
    Ok(candidate)
}

fn legacy_scope(plan: &plan::Plan) -> io::Result<&super::legacy_scope::Scope> {
    plan.legacy_scope
        .as_ref()
        .ok_or_else(|| err("нет наборов старой DNS-политики"))
}

fn legacy_classifier(plan: &plan::Plan, policy: &Routing) -> io::Result<Policy> {
    Ok(Policy::compile_legacy_full(policy)?
        .with_legacy_ingress(legacy_scope(plan)?.ingress_bindings()?))
}

fn learn_legacy(
    installed: &plan::Plan,
    policy: &Routing,
    answer: &Answer<'_>,
    origin: DnsOrigin<'_>,
    name: Option<&str>,
    members: &mut Vec<Member>,
) -> io::Result<Applied> {
    let name = name.ok_or_else(|| err("требуется проверенное имя старой DNS-политики"))?;
    let rules = legacy_classifier(installed, policy)?;
    let client = origin
        .client
        .filter(|ip| rules.legacy_accepts_peer(*ip, origin.ingress));
    if rules.matched(name, client) != Some(answer.zone) {
        return Err(err(
            "имя или клиент не соответствуют правилу старой DNS-политики",
        ));
    }
    let mut accepted = Vec::new();
    let tunnel = policy.zones[answer.zone].direction() == "tunnel";
    let no_v6 = installed.legacy_full != Some(plan::LegacyFull::Dual);
    if tunnel
        && no_v6
        && (answer.qtype == 28
            || matches!(answer.qtype, 64 | 65)
                && answer
                    .addresses
                    .iter()
                    .any(|ip| ip.to_canonical().is_ipv6()))
    {
        return Ok(Applied {
            suppress: true,
            accepted,
        });
    }
    let Some(source) = client.map(|ip| ip.to_canonical()) else {
        return Ok(Applied {
            suppress: false,
            accepted,
        });
    };
    let scope = legacy_scope(installed)?;
    let groups = rules.legacy_dns_zones(name, Some(source));
    let ips = answer
        .addresses
        .iter()
        .map(|ip| ip.to_canonical())
        .collect::<std::collections::BTreeSet<_>>();
    if !groups.is_empty() && ips.len() > 64 {
        return Err(err("DNS-ответ содержит больше 64 маршрутизируемых адресов"));
    }
    if !groups.is_empty()
        && !ips.is_empty()
        && origin
            .ingress
            .is_none_or(|bridge| !scope.accepts_client(source, bridge))
    {
        return Err(err("не подтверждён исходный LAN-мост клиента DNS"));
    }
    if groups.iter().any(|zone| {
        ips.iter().any(|ip| {
            !plan::Prefix::host(*ip).safe() || !scope.permits_source_member(*zone, source, *ip)
        })
    }) {
        return Err(err(
            "DNS-адрес или клиент не подтверждён в старом наборе зоны",
        ));
    }
    for zone in groups {
        for &ip in &ips {
            // Go's source-zone sets are hash:net without a member timeout.
            remember(members, zone, ip, u64::MAX, 0)?;
            if zone == answer.zone {
                accepted.push(ip);
            }
        }
    }
    Ok(Applied {
        suppress: false,
        accepted,
    })
}

fn learn_archive_members(
    plan: &plan::Plan,
    policy: &Routing,
    doc: &Value,
    answer: ArchiveAnswer<'_>,
    members: &mut Vec<Member>,
    now: u64,
) -> io::Result<Vec<IpAddr>> {
    if !matches!(answer.qtype, 1 | 28)
        || answer.ttl == 0
        || answer.addresses.len() > 128
        || answer
            .addresses
            .iter()
            .any(|&ip| ip.is_ipv4() != (answer.qtype == 1) || !plan::Prefix::host(ip).safe())
    {
        return Err(err("архивный DNS-ответ содержит недопустимые адреса"));
    }
    if plan.go_ipv4 && answer.qtype == 28 {
        return Ok(Vec::new());
    }
    let names = Policy::compile(policy)?;
    let until = now.saturating_add(u64::from(answer.ttl));
    let mut accepted = std::collections::BTreeSet::new();
    for index in names.archive_zones(answer.name, answer.qtype) {
        let zone = &policy.zones[index];
        let (v4, v6) = dns::families(doc, zone);
        if (answer.qtype == 1 && !v4) || (answer.qtype == 28 && !v6) {
            continue;
        }
        for &ip in answer.addresses {
            if zone.direction() == "direct" && shared_cdn_address(ip) {
                continue;
            }
            remember(members, index, ip, until, 0)?;
            accepted.insert(ip);
        }
    }
    Ok(accepted.into_iter().collect())
}

fn learn(
    db: &Store,
    run: &dyn Runner,
    request: Learn<'_>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
    before_change: impl FnOnce() -> io::Result<()>,
) -> io::Result<Applied> {
    let (revision, addresses, client) = match &request {
        Learn::Client(answer, origin, _) => (answer.revision, answer.addresses, origin.client),
        Learn::Archive(answer) => (answer.revision, answer.addresses, None),
    };
    let now = nfqws2_awg_profile::now();
    db.transaction(|tx| {
        let old = Journal::read(db)?;
        if super::mtu_edit::pending_mtu_edit(db)?
            || super::active_replacement::pending_dns_settlement(db)?
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let saved = old
            .installed
            .learned
            .as_ref()
            .ok_or_else(|| err("DNS-политика снята"))?;
        if old.installed.revision != revision
            || !old.preparing.is_empty()
            || old.expires != 0 && now >= old.expires
        {
            return Err(err("изменилась активная DNS-политика"));
        }
        let policy = saved.routing()?;
        let doc = nfqws2_awg_profile::read(db)?;
        let predecessor = super::mtu_edit::pending_predecessor(db, &doc, &old)?;
        if predecessor.is_none() && super::mtu_edit::saved_profile(&doc, &old)?.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut k = kernel(run);
        k.track_sockets(&doc, &old.installed);
        if old.boot != boot_id(&k)? {
            return Err(err("требуется восстановление маршрутов после загрузки"));
        }
        k.check_lan_zone(&old.installed)?;
        let mut members = saved.members.clone();
        members.retain(|v| v.until > now);
        let (mut candidate, accepted) = if old.installed.legacy_full.is_some() {
            let Learn::Client(answer, origin, name) = request else {
                return Err(err("архивное обучение требует зональную DNS-политику"));
            };
            let answer =
                learn_legacy(&old.installed, &policy, &answer, origin, name, &mut members)?;
            if answer.suppress {
                return Ok(answer);
            }
            (legacy_candidate(&old.installed, members)?, answer.accepted)
        } else {
            let (accepted, suppress) = match request {
                Learn::Archive(answer) => {
                    let accepted = learn_archive_members(
                        &old.installed,
                        &policy,
                        &doc,
                        answer,
                        &mut members,
                        now,
                    )?;
                    if accepted.is_empty() {
                        return Ok(Applied {
                            suppress: false,
                            accepted,
                        });
                    }
                    (accepted, false)
                }
                Learn::Client(answer, origin, name) => {
                    let zone = policy
                        .zones
                        .get(answer.zone)
                        .filter(|z| {
                            z.enabled
                                && !z.waiting_for_connection
                                && (!z.domains.is_empty() || z.dns_catch_all())
                        })
                        .ok_or_else(|| err("нет активного DNS-правила"))?;
                    let (v4, v6) = dns::families(&doc, zone);
                    let v6 = v6 && !old.installed.go_ipv4;
                    let tunnel = zone.direction() == "tunnel";
                    let suppress = tunnel
                        && ((!v6 && answer.qtype == 28)
                            || (!v4 && answer.qtype == 1)
                            || answer
                                .addresses
                                .iter()
                                .any(|ip| if ip.is_ipv6() { !v6 } else { !v4 }));
                    let lan_direct = !tunnel && zone.source_ips.is_empty();
                    if zone.only_catch_all() && old.installed.ordered_default {
                        return Ok(Applied {
                            suppress,
                            accepted: Vec::new(),
                        });
                    }
                    let mut accepted = Vec::new();
                    // Transparent multi-zone Go membership is retained until
                    // a policy rebuild, separately from the delivered RR TTL.
                    let until = if super::active_replacement::retains_mixed_firmware_member(
                        &old, &doc, &policy, &answer, origin, name,
                    )? {
                        super::active_replacement::RETAINED_FIRMWARE_MEMBER
                    } else {
                        now.saturating_add(u64::from(answer.ttl.max(1)))
                    };
                    for &ip in answer.addresses.iter().filter(|_| !suppress) {
                        if old.installed.go_ipv4 && ip.is_ipv6() {
                            continue;
                        }
                        if !plan::Prefix::host(ip).safe() {
                            return Err(err("DNS-ответ содержит служебный адрес"));
                        }
                        if lan_direct && shared_cdn_address(ip) {
                            continue;
                        }
                        accepted.push(ip);
                        remember(&mut members, answer.zone, ip, until, 300)?;
                    }
                    (accepted, suppress)
                }
            };
            let mut candidate = plan::compile_saved_policy(
                &doc,
                policy,
                old.installed.revision,
                None,
                &members,
                false,
                old.installed.layout(),
            )?;
            candidate.firewall = old.installed.firewall;
            candidate.fw4_zone.clone_from(&old.installed.fw4_zone);
            candidate
                .local_sources
                .clone_from(&old.installed.local_sources);
            candidate.set_dns_bridges(&old.installed.dns_bridges)?;
            if candidate.learned.as_ref().map(|s| &s.hash) != Some(&saved.hash) {
                return Err(err("изменился профиль активной DNS-политики"));
            }
            if suppress {
                return Ok(Applied {
                    suppress: true,
                    accepted,
                });
            }
            (candidate, accepted)
        };
        let transient = super::legacy_watchdog::is_transient(&old.committed, &old.installed);
        let mut resolved = if candidate.legacy_full.is_some() {
            super::legacy_watchdog::resolve_legacy_transport(
                &doc,
                candidate.clone(),
                Some(&old.installed),
                plan::Verification::Read(&k),
                peer,
            )?
        } else {
            plan::restore_with_predecessor(
                &doc,
                &candidate,
                Some(&old.installed),
                &k,
                predecessor.as_ref(),
                peer,
            )?
        };
        if predecessor.is_some() && !resolved.predecessor_verified {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if transient {
            if let Some(confirmed) = &old.committed.full_endpoints {
                resolved.endpoints.extend(confirmed.iter().copied());
                resolved.plan.full_endpoints = Some(resolved.endpoints.clone());
                resolved.plan.validate()?;
            }
        }
        candidate.mss.clone_from(&resolved.plan.mss);
        // A client may use a separate address family to query its resolver.
        // Without a matching-family address, check every possible source.
        if !resolved.plan.fully_live()
            && (candidate.legacy_full.is_some() && !addresses.is_empty()
                || resolved.plan.flows().any(|(s, primary)| {
                    resolved.plan.effective(s, primary).is_none()
                        && client
                            .map(|ip| ip.to_canonical())
                            .filter(|source| plan::Family::of(*source) == s.dest.family())
                            .is_none_or(|source| resolved.plan.matches_source(s, source))
                        && accepted.iter().any(|ip| s.dest.contains(*ip))
                }))
        {
            return Err(err("нет доступного пира для DNS-ответа"));
        }
        k.guard(&resolved.plan, &resolved.endpoints)?;
        let mut next = old.clone();
        next.installed = resolved.plan.into();
        if old.expires == 0 && !transient {
            next.committed = if &candidate == next.installed.as_ref() {
                next.installed.clone()
            } else {
                candidate.into()
            };
        }
        let installed = objects(&old.installed);
        let ttl_only = old.installed.packed
            && installed == objects(&next.installed)
            && old.installed.selected == next.installed.selected
            && old.installed.offline == next.installed.offline;
        if (next == old || ttl_only) && k.inventory(&old.claims(), true)? == installed {
            if next != old {
                // Only the expiration times changed. No FIB change or confirmation
                // invalidation is needed; the previous policy remains usable.
                tx.save_runtime_bounded(super::RECEIPT, &next, super::RECEIPT_LIMIT)?;
            }
            return Ok(Applied {
                suppress: false,
                accepted,
            });
        }
        let rollback = (!resolved.unsafe_previous.is_empty()).then(|| {
            let mut parked = old.clone();
            parked.installed.park(&resolved.unsafe_previous);
            parked
        });
        // Invalidate concurrent confirmations before changing the FIB. Even a
        // pure addition may need a non-additive rollback on a command failure.
        before_change()?;
        if super::acceleration::learning_paused(db)? {
            super::switch_routes(db, tx, run, &old, &next, rollback.as_ref())?;
        } else {
            transition(db, tx, run, &old, &next, rollback.as_ref())?;
        }
        Ok(Applied {
            suppress: false,
            accepted,
        })
    })
}

pub(super) fn expire(doc: &Value, plan: &plan::Plan, now: u64) -> io::Result<Option<plan::Plan>> {
    let Some(saved) = &plan.learned else {
        return Ok(None);
    };
    if saved.members.iter().all(|m| m.until > now) {
        return Ok(None);
    }
    let live = saved
        .members
        .iter()
        .filter(|m| m.until > now)
        .cloned()
        .collect::<Vec<_>>();
    if plan.legacy_full.is_some() {
        return legacy_candidate(plan, live).map(Some);
    }
    let mut candidate = plan::compile_saved_policy(
        doc,
        saved.routing()?,
        plan.revision,
        None,
        &live,
        false,
        plan.layout(),
    )?;
    candidate.firewall = plan.firewall;
    candidate.fw4_zone.clone_from(&plan.fw4_zone);
    candidate.local_sources.clone_from(&plan.local_sources);
    candidate.set_dns_bridges(&plan.dns_bridges)?;
    if candidate.learned.as_ref().map(|s| &s.hash) != Some(&saved.hash) {
        return Err(err("изменились профили динамических зон"));
    }
    Ok(Some(candidate))
}

#[cfg(test)]
mod legacy_full_tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (plan::Plan, Routing) {
        let mut zones = [1, 2].map(|rule| {
            json!({"index":rule-1,"rule":rule,"tunnel":rule==2,
                "sources":["192.168.1.0/24","192.168.1.9"],"addresses":{"192.168.1.0/24":"br0"},
                "v4":true,"v6":true,"networks":[],
                "devices":{"192.168.1.9":{"bridge":"br0","mac":"00:20:30:40:50:60"}}})
        });
        let scope = serde_json::from_value(json!({
            "zones":[zones[0].take(),zones[1].take()],
            "bridges":{"192.168.1.0/24":"br0","192.168.1.9":"br0"}
        }))
        .unwrap();
        let plan = plan::Plan {
            legacy_full: Some(plan::LegacyFull::Dual),
            legacy_scope: Some(scope),
            ..Default::default()
        };
        let routing = serde_json::from_value(json!({"mode":"full","zones":[
            {"enabled":true,"route":"tunnel","domains":["office.test"]},
            {"enabled":true,"route":"direct","domains":["office.test"],"source_ips":["192.168.1.0/24","192.168.1.9"]},
            {"enabled":true,"route":"tunnel","domains":["*.office.test"],"source_ips":["192.168.1.0/24","192.168.1.9"]}
        ]})).unwrap();
        (plan, routing)
    }

    #[test]
    fn a_global_winner_still_learns_both_source_sets_for_the_real_client() {
        let (plan, policy) = fixture();
        let v4 = "192.0.2.6".parse().unwrap();
        let v6 = "2001:db8::34".parse().unwrap();
        let ips = [v4, "::ffff:192.0.2.6".parse().unwrap(), v6];
        let mut learned = Vec::new();
        let answer = Answer {
            revision: 5,
            zone: 0,
            addresses: &ips,
            ttl: 10,
            qtype: 65,
        };
        let name = Some("edge.office.test");
        let client = Some("::ffff:192.168.1.9".parse().unwrap());
        for ingress in [None, Some("br-guest"), Some("lo")] {
            let origin = DnsOrigin { client, ingress };
            let applied =
                learn_legacy(&plan, &policy, &answer, origin, name, &mut learned).unwrap();
            assert!(!applied.suppress && learned.is_empty());
        }
        let origin = DnsOrigin {
            client,
            ingress: Some("br0"),
        };
        let applied = learn_legacy(&plan, &policy, &answer, origin, name, &mut learned).unwrap();
        assert!(!applied.suppress && applied.accepted.is_empty());
        assert_eq!(
            learned
                .iter()
                .map(|m| (m.zone, m.ip, m.until))
                .collect::<Vec<_>>(),
            [
                (1, v4, u64::MAX),
                (1, v6, u64::MAX),
                (2, v4, u64::MAX),
                (2, v6, u64::MAX)
            ]
        );
        let saved = learned.clone();
        let impostor = Answer { zone: 2, ..answer };
        assert!(learn_legacy(&plan, &policy, &impostor, origin, name, &mut learned).is_err());
        let missing_device = DnsOrigin {
            client: Some("192.168.1.19".parse().unwrap()),
            ..origin
        };
        assert!(learn_legacy(&plan, &policy, &answer, missing_device, name, &mut learned).is_err());
        assert_eq!(learned, saved);
    }

    #[test]
    fn ip_families_are_filtered_only_for_an_explicit_tunnel_winner() {
        let (mut plan, policy) = fixture();
        plan.legacy_full = Some(plan::LegacyFull::Ipv4Only);
        let origin = DnsOrigin {
            client: Some("192.168.1.9".parse().unwrap()),
            ingress: Some("br0"),
        };
        let mut members = Vec::new();
        let addresses = ["2001:db8::34".parse().unwrap()];
        for qtype in [28, 64, 65] {
            let answer = Answer {
                revision: 5,
                zone: 0,
                addresses: &addresses,
                ttl: 10,
                qtype,
            };
            let applied = learn_legacy(
                &plan,
                &policy,
                &answer,
                origin,
                Some("office.test"),
                &mut members,
            )
            .unwrap();
            assert!(applied.suppress && members.is_empty());
        }
        let address = ["::ffff:192.0.2.6".parse().unwrap()];
        let answer = Answer {
            revision: 5,
            zone: 0,
            addresses: &address,
            ttl: 10,
            qtype: 65,
        };
        assert!(
            !learn_legacy(
                &plan,
                &policy,
                &answer,
                origin,
                Some("office.test"),
                &mut members
            )
            .unwrap()
            .suppress
        );
    }

    #[test]
    fn a_scoped_winner_is_rejected_when_the_packet_arrived_on_another_bridge() {
        let (plan, mut policy) = fixture();
        policy.zones[0].domains[0] = "other.test".into();
        let client = Some("192.168.1.9".parse().unwrap());
        let addresses = ["198.51.100.34".parse().unwrap()];
        let answer = Answer {
            revision: 5,
            zone: 1,
            addresses: &addresses,
            ttl: 300,
            qtype: 1,
        };
        let mut members = Vec::new();
        for ingress in [None, Some("lo"), Some("br-guest")] {
            let origin = DnsOrigin { client, ingress };
            assert!(learn_legacy(
                &plan,
                &policy,
                &answer,
                origin,
                Some("office.test"),
                &mut members
            )
            .is_err());
            assert!(members.is_empty());
        }
        let origin = DnsOrigin {
            client,
            ingress: Some("br0"),
        };
        assert_eq!(
            learn_legacy(
                &plan,
                &policy,
                &answer,
                origin,
                Some("office.test"),
                &mut members
            )
            .unwrap()
            .accepted,
            addresses
        );
    }
}
