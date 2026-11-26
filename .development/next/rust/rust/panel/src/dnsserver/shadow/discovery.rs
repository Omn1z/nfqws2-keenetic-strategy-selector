use super::{
    super::{config::invalid, lan},
    diagnostics::Trace,
    inform::state::{KnownTarget, Source as InformSource, Wan as InformWan},
    observer::{self, Candidate, Target, Wan},
    renew::capture::Observation,
};
use nfqws2_router_command::{Runner, System};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::{Duration, Instant},
};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub addr: SocketAddr,
    pub device: String,
    pub expires: Option<Instant>,
}
pub(super) trait Source: Send + Sync {
    fn read(&self, retained: &[History]) -> io::Result<Evidence>;
    fn read_with_inform(
        &self,
        retained: &[History],
        _: &[KnownTarget],
        _: Instant,
    ) -> io::Result<Evidence> {
        self.read(retained)
    }
    fn read_traced(
        &self,
        retained: &[History],
        known: &[KnownTarget],
        deadline: Instant,
        _: &Trace,
    ) -> io::Result<Evidence> {
        self.read_with_inform(retained, known, deadline)
    }
    fn confirm_inform(&self, _: &InformWan, _: Instant) -> bool {
        false
    }
    fn target(&self, _: &Evidence, _: Option<&Candidate>) -> Option<Target> {
        None
    }
}
pub(super) struct Firmware(pub(super) Vec<String>);

#[derive(Clone)]
pub(super) struct History {
    pub(super) key: String,
    pub(super) iface: String,
    pub(super) client: Ipv4Addr,
    pub(super) stamp: String,
    pub(super) lease_seconds: u32,
    pub(super) observed_at: Option<OffsetDateTime>,
    pub(super) expires: Instant,
    pub(super) peers: Vec<Peer>,
    at: Option<OffsetDateTime>,
    bound: bool,
    current: bool,
}

impl History {
    pub(super) fn from_saved(iface: String, saved: super::lease_store::Lease) -> Self {
        Self {
            key: saved.wan_key,
            iface,
            client: saved.client,
            stamp: saved.stamp,
            lease_seconds: saved.lease_seconds,
            observed_at: saved.observed_at,
            expires: saved.expires,
            peers: saved
                .servers
                .into_iter()
                .map(|addr| Peer {
                    addr,
                    device: String::new(),
                    expires: Some(saved.expires),
                })
                .collect(),
            at: saved.observed_at,
            bound: false,
            current: false,
        }
    }

    pub(super) fn to_saved(&self) -> super::lease_store::Lease {
        super::lease_store::Lease {
            wan_key: self.key.clone(),
            client: self.client,
            servers: self.peers.iter().map(|peer| peer.addr).collect(),
            expires: self.expires,
            stamp: self.stamp.clone(),
            lease_seconds: self.lease_seconds,
            observed_at: self.observed_at,
        }
    }
}

pub(super) struct Evidence {
    pub(super) peers: Vec<Peer>,
    pub(super) history: Vec<History>,
    pub(super) candidates: Vec<Candidate>,
    pub(super) wan_key: String,
    pub(super) authoritative: bool,
    pub(super) inform: InformEvidence,
    inform_authoritative: bool,
    inform_candidates: Vec<Candidate>,
    hosts: Vec<(String, IpAddr)>,
    fresh: Vec<(String, OffsetDateTime)>,
    error: Option<io::Error>,
}

#[derive(Default)]
pub(super) struct InformEvidence {
    pub(super) owners: Vec<InformWan>,
    pub(super) local: Vec<Ipv4Addr>,
    pub(super) wan_ips: Vec<Ipv4Addr>,
    pub(super) ring: Vec<KnownTarget>,
    pub(super) restored: Vec<KnownTarget>,
    pub(super) router_now: Option<OffsetDateTime>,
}

pub(super) struct Finished {
    pub(super) result: io::Result<Vec<Peer>>,
    pub(super) history: Vec<History>,
    pub(super) source: InformSource,
    pub(super) ppp: Vec<Peer>,
    pub(super) native_applied: Option<InformWan>,
    pub(super) inform: InformEvidence,
}

impl Evidence {
    pub(super) fn has_authority_for_leases(&self) -> bool {
        self.authoritative || !self.wan_key.is_empty()
    }

    fn bind_inform(
        &mut self,
        live: &[(String, IpAddr)],
        mut identity: impl FnMut(&str) -> io::Result<(u32, [u8; 6])>,
    ) {
        let mut links = HashMap::new();
        self.inform.owners = std::mem::take(&mut self.inform_candidates)
            .into_iter()
            .filter_map(|candidate| {
                let mut owners = live.iter().filter(|(_, ip)| *ip == candidate.client);
                let (owner, _) = owners.next()?;
                if *owner != candidate.device
                    || owners.any(|(device, _)| *device != candidate.device)
                {
                    return None;
                }
                let (index, mac) = *links
                    .entry(candidate.device.clone())
                    .or_insert_with(|| identity(&candidate.device).ok())
                    .as_ref()?;
                Some(InformWan {
                    key: self.wan_key.clone(),
                    iface: candidate.iface,
                    device: candidate.device,
                    index,
                    mac,
                    client: candidate.client,
                })
            })
            .collect();
        self.inform.local = local_v4(live);
        let eligible = |hint: &KnownTarget| {
            !self.inform.local.contains(&hint.server)
                && self
                    .inform
                    .owners
                    .iter()
                    .any(|owner| owner.iface == hint.iface && owner.client == hint.client)
        };
        self.inform.ring.retain(eligible);
        self.inform.restored.retain(eligible);
    }

    #[cfg(test)]
    pub(super) fn fixture(peers: Vec<Peer>) -> Self {
        Self {
            peers,
            history: Vec::new(),
            candidates: Vec::new(),
            wan_key: String::new(),
            authoritative: false,
            inform: InformEvidence::default(),
            inform_authoritative: false,
            inform_candidates: Vec::new(),
            hosts: Vec::new(),
            fresh: Vec::new(),
            error: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_fixture_target(mut self, target: &Target) -> Self {
        self.wan_key = target.wan_key.clone();
        self.hosts.push((
            target.candidate.device.clone(),
            target.candidate.client.into(),
        ));
        self
    }

    #[cfg(test)]
    pub(super) fn finish(
        self,
        current: Option<(&Target, &super::renew::capture::Receipt)>,
    ) -> (io::Result<Vec<Peer>>, Vec<History>) {
        let finished = self.finish_inform(current);
        (finished.result, finished.history)
    }

    pub(super) fn finish_inform(
        mut self,
        current: Option<(&super::observer::Target, &super::renew::capture::Receipt)>,
    ) -> Finished {
        let now = Instant::now();
        self.history.retain(|lease| lease.expires > now);
        let mut applied = None;
        if let Some((target, receipt)) =
            current.filter(|(target, _)| target.wan_key == self.wan_key)
        {
            let candidate = &target.candidate;
            let same =
                |lease: &History| lease.key == target.wan_key && lease.client == candidate.client;
            if !self.history.iter().any(|lease| {
                lease.current && same(lease) && lease.at.is_some_and(|at| at > receipt.observed_at)
            }) {
                applied = Some(InformWan {
                    key: target.wan_key.clone(),
                    iface: candidate.iface.clone(),
                    device: candidate.device.clone(),
                    index: target.index,
                    mac: target.mac,
                    client: candidate.client,
                });
                self.history.retain(|lease| !same(lease));
                if let Observation::Dns {
                    servers,
                    expires_at,
                    lease_seconds,
                } = &receipt.observation
                {
                    let expires = expires_at.into_std();
                    if now < expires {
                        let peers = lease_peers(
                            servers.iter().copied().map(IpAddr::from),
                            &candidate.device,
                            &self.hosts,
                            expires,
                        );
                        if !peers.is_empty() {
                            self.history.push(History {
                                key: target.wan_key.clone(),
                                iface: candidate.iface.clone(),
                                client: candidate.client,
                                stamp: String::new(),
                                lease_seconds: *lease_seconds,
                                observed_at: Some(receipt.observed_at),
                                at: Some(receipt.observed_at),
                                expires,
                                peers,
                                bound: true,
                                current: true,
                            });
                        }
                    }
                }
            }
        }
        self.peers
            .retain(|peer| peer.expires.is_none_or(|expires| expires > now));
        let ppp = if self.inform_authoritative {
            Vec::new()
        } else {
            self.peers.clone()
        };
        let mut native_lease = false;
        if applied.is_none() {
            for (iface, at) in &self.fresh {
                if let Some(lease) = self
                    .history
                    .iter()
                    .find(|lease| lease.current && &lease.iface == iface && lease.at == Some(*at))
                {
                    native_lease |=
                        extend(&mut self.peers, &lease.peers) && lease.observed_at.is_some();
                }
            }
        }
        if self.peers.is_empty() {
            for lease in self.history.iter().filter(|lease| lease.current) {
                native_lease |=
                    extend(&mut self.peers, &lease.peers) && lease.observed_at.is_some();
            }
        }
        let result = if self.peers.is_empty() {
            Err(self
                .error
                .unwrap_or_else(|| invalid("активный WAN не сообщил подходящий DNS провайдера")))
        } else {
            Ok(self.peers)
        };
        let source = if self.inform_authoritative {
            InformSource::Authoritative
        } else if native_lease {
            InformSource::NativeLease
        } else {
            InformSource::Fallback {
                has_verified_peer: result.is_ok(),
            }
        };
        Finished {
            result,
            history: self.history,
            source,
            ppp,
            native_applied: applied,
            inform: self.inform,
        }
    }
}

#[cfg(test)]
mod tests;

fn extend(out: &mut Vec<Peer>, input: &[Peer]) -> bool {
    let baseline = out.len();
    for peer in input {
        if out.len() >= 8 {
            break;
        }
        if !out.iter().any(|p| p.addr == peer.addr) {
            out.push(peer.clone());
        }
    }
    out.len() != baseline
}

fn lease_peers(
    dns: impl IntoIterator<Item = IpAddr>,
    device: &str,
    hosts: &[(String, IpAddr)],
    expires: Instant,
) -> Vec<Peer> {
    let mut peers = Vec::new();
    for ip in dns {
        add(&mut peers, Some(SocketAddr::new(ip, 53)), device, hosts);
    }
    for peer in &mut peers {
        peer.expires = Some(expires);
    }
    peers
}
pub(super) fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_link_local()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || {
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_unicast_link_local()
            },
            |v| usable(v.into()),
        ),
    }
}
pub(super) fn wan(device: &str) -> bool {
    !device.is_empty()
        && device.len() <= 15
        && device != "lo"
        && device
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && (device == "br-wan"
            || device.starts_with("br-wan.")
            || !["awg", "nwg", "wg", "tun", "tap", "br", "docker", "veth"]
                .iter()
                .any(|p| device.starts_with(p)))
}
pub(crate) fn native(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
        && ![
            "Wireguard",
            "OpenVPN",
            "L2TP",
            "PPTP",
            "SSTP",
            "IPsec",
            "Bridge",
        ]
        .iter()
        .any(|p| name.starts_with(p))
}
fn address(text: &str) -> Option<SocketAddr> {
    text.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .ok()
        .or_else(|| text.parse::<SocketAddr>().ok())
}
fn add(
    out: &mut Vec<Peer>,
    candidate: Option<SocketAddr>,
    device: &str,
    hosts: &[(String, IpAddr)],
) {
    let Some(addr) = candidate.map(|v| SocketAddr::new(v.ip().to_canonical(), v.port())) else {
        return;
    };
    if !usable(addr.ip())
        || addr.port() == 0
        || !wan(device)
        || !hosts.iter().any(|(n, _)| n == device)
        || hosts
            .iter()
            .any(|(_, ip)| ip.to_canonical() == addr.ip().to_canonical())
    {
        return;
    }
    if out.len() < 8 && !out.iter().any(|p| p.addr == addr) {
        out.push(Peer {
            addr,
            device: device.into(),
            expires: None,
        });
    }
}
pub(crate) fn defaults(output: &str) -> HashSet<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut words = line.split_ascii_whitespace();
            if words.next() != Some("default") {
                return None;
            }
            words.find(|w| *w == "dev")?;
            words.next().filter(|d| wan(d)).map(str::to_owned)
        })
        .collect()
}
// Finalize each router record as the next section starts. Static entries
// may precede the first provider record, even in very long configurations.
fn native_servers(text: &str) -> impl Iterator<Item = (&str, SocketAddr)> {
    #[derive(Default)]
    struct Row<'a> {
        iface: &'a str,
        address: &'a str,
        port: &'a str,
        service: &'a str,
    }
    let mut current: Option<Row<'_>> = None;
    text.lines().chain(["server:"]).filter_map(move |line| {
        let (key, value) = line.trim().trim_start_matches("\x1b[K").split_once(':')?;
        let (key, value) = (key.trim(), value.trim());
        if matches!(key, "server" | "server-tls" | "server-https") {
            let row = current.take();
            current = (key == "server").then(Row::default);
            let row = row?;
            if !native(row.iface)
                || !row
                    .service
                    .split(|c: char| !c.is_ascii_alphabetic())
                    .any(|s| {
                        ["dhcp", "ppp", "ipcp", "pppoe", "dhcpv"]
                            .iter()
                            .any(|p| s.eq_ignore_ascii_case(p))
                    })
            {
                return None;
            }
            let port = match row.port {
                "" | "0" => 53,
                s => s.parse::<u16>().ok().filter(|n| *n > 0)?,
            };
            return Some((row.iface, SocketAddr::new(row.address.parse().ok()?, port)));
        }
        let row = current.as_mut()?;
        match key {
            "address" => row.address = value,
            "port" => row.port = value,
            "interface" => row.iface = value,
            "service" => row.service = value,
            _ => (),
        }
        None
    })
}
struct Query<'a> {
    retained: &'a [History],
    known: &'a [KnownTarget],
    deadline: Instant,
    trace: &'a Trace,
}

fn iface_owner(txt: &str) -> Option<Vec<IpAddr>> {
    let kv = txt
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()));
    let mut connected = kv
        .clone()
        .filter_map(|(k, v)| (k == "connected").then_some(v));
    if connected.next() != Some("yes") || connected.next().is_some() {
        return None;
    }
    Some(
        kv.filter(|(k, _)| *k == "address")
            .filter_map(|(_, s)| s.parse::<IpAddr>().ok())
            .collect(),
    )
}

fn local_v4(hosts: &[(String, IpAddr)]) -> Vec<Ipv4Addr> {
    hosts
        .iter()
        .filter_map(|(_, ip)| match ip.to_canonical() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect()
}

fn confirm_inform_with(
    run: &dyn Runner,
    configured: &[String],
    hosts: impl Fn() -> io::Result<Vec<(String, IpAddr)>>,
    expected: &InformWan,
    deadline: Instant,
    identity: impl FnOnce(&str) -> io::Result<(u32, [u8; 6])>,
) -> bool {
    if !native(&expected.iface) || Instant::now() >= deadline {
        return false;
    }
    let current = |hosts: &[(String, IpAddr)]| {
        let routes = run
            .run_bounded(
                "ip",
                &["-4", "route", "show", "table", "main", "default"],
                deadline,
                128 << 10,
            )
            .ok()?;
        Wan::read(&routes, configured, hosts).filter(|wan| wan.key == expected.key)
    };
    let Ok(before) = hosts() else {
        return false;
    };
    let Some(wan) = current(&before) else {
        return false;
    };
    let read = |operation: &str| {
        run.run_bounded("ndmc", &["-c", operation], deadline, 128 << 10)
            .ok()
            .filter(|text| !super::renew::native_error(text))
    };
    let Some(interfaces) = read("show interface") else {
        return false;
    };
    if !wan
        .candidates(&interfaces, &before)
        .iter()
        .any(|owner| owner.device == expected.device && owner.client == expected.client)
    {
        return false;
    }
    let named =
        read(&format!("show interface {}", expected.iface)).and_then(|text| iface_owner(&text));
    if !named.is_some_and(|ips| ips.contains(&expected.client.into()))
        || !identity(&expected.device).is_ok_and(|link| link == (expected.index, expected.mac))
    {
        return false;
    }
    let Ok(after) = hosts() else {
        return false;
    };
    let mut owners = after.iter().filter(|(_, ip)| *ip == expected.client);
    owners
        .next()
        .is_some_and(|(owner, _)| *owner == expected.device)
        && !owners.any(|(owner, _)| *owner != expected.device)
        && current(&after).is_some()
        && Instant::now() < deadline
}

fn collect_with_inform(
    run: &dyn Runner,
    openwrt: bool,
    configured: &[String],
    hosts: &[(String, IpAddr)],
    query: Query<'_>,
) -> io::Result<Evidence> {
    let Query {
        retained,
        known,
        deadline,
        trace,
    } = query;
    let configured_hosts = hosts
        .iter()
        .filter(|(device, _)| configured.contains(device));
    let ipv4 = configured_hosts
        .clone()
        .filter(|(_, ip)| ip.is_ipv4())
        .count();
    let ipv6 = configured_hosts.filter(|(_, ip)| ip.is_ipv6()).count();
    trace.step(
        "wan.addresses",
        &format!("Адреса настроенных WAN: IPv4={ipv4}, IPv6={ipv6}"),
    );
    let mut out = Vec::new();
    if openwrt {
        let mut main = HashSet::new();
        for family in ["-4", "-6"] {
            if let Ok(txt) = run.run(
                "ip",
                &[family, "route", "show", "table", "main", "default"],
                deadline,
            ) {
                main.extend(defaults(&txt));
            }
        }
        let started = Instant::now();
        let txt = run.run("ubus", &["call", "network.interface", "dump"], deadline);
        if txt.is_err() {
            trace.timed(
                "openwrt.dns",
                "ubus: прочитан=false; принято DNS-серверов: 0",
                started.elapsed(),
            );
        }
        let txt = txt?;
        let json: Value = serde_json::from_str(&txt)?;
        for iface in json["interface"].as_array().into_iter().flatten() {
            if iface["up"] != true
                || !matches!(
                    iface["proto"].as_str(),
                    Some(
                        "dhcp"
                            | "dhcpv6"
                            | "static"
                            | "pppoe"
                            | "pppoa"
                            | "3g"
                            | "qmi"
                            | "ncm"
                            | "mbim"
                            | "modemmanager"
                            | "wwan"
                            | "6in4"
                            | "6rd"
                            | "dslite"
                            | "464xlat"
                            | "map"
                    )
                )
            {
                continue;
            }
            let l3 = iface["l3_device"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| iface["device"].as_str())
                .unwrap_or("");
            if !wan(l3)
                || (!main.contains(l3)
                    && !configured
                        .iter()
                        .any(|n| n == l3 || iface["device"] == *n || iface["interface"] == *n))
            {
                continue;
            }
            let names = iface["inactive"]["dns-server"]
                .as_array()
                .filter(|a| !a.is_empty())
                .or_else(|| iface["dns-server"].as_array());
            for dns in names.into_iter().flatten().filter_map(Value::as_str) {
                add(&mut out, address(dns), l3, hosts);
            }
        }
        trace.timed(
            "openwrt.dns",
            &format!("ubus: прочитан=true; принято DNS-серверов: {}", out.len()),
            started.elapsed(),
        );
        let inform_authoritative = !out.is_empty();
        return Ok(Evidence {
            peers: out,
            history: Vec::new(),
            candidates: Vec::new(),
            wan_key: String::new(),
            authoritative: false,
            inform: InformEvidence {
                local: local_v4(hosts),
                ..InformEvidence::default()
            },
            inform_authoritative,
            inform_candidates: Vec::new(),
            hosts: Vec::new(),
            fresh: Vec::new(),
            error: None,
        });
    }
    let known_error = std::cell::Cell::new(None);
    let read = |operation: &str| -> io::Result<String> {
        let started = Instant::now();
        let result = if operation == "show log" {
            run.run_tail("ndmc", &["-c", operation], deadline, 1 << 20)
        } else {
            run.run_bounded("ndmc", &["-c", operation], deadline, 128 << 10)
        }
        .and_then(|text| {
            if super::renew::native_error(&text) {
                Err(io::Error::other("не удалось прочитать состояние Keenetic"))
            } else {
                Ok(text)
            }
        });
        trace.native_command(operation, result.is_ok(), started.elapsed());
        if let Err(error) = &result {
            if known_error.get().is_none() {
                known_error.set(Some(error.kind()));
            }
        }
        result
    };
    if let Ok(txt) = read("show ip name-server") {
        let mut verified = HashMap::new();
        let mut records = 0;
        for (iface, addr) in native_servers(&txt).take(32) {
            records += 1;
            let device = verified.entry(iface).or_insert_with(|| {
                let device = read(&format!("show interface {iface}"))
                    .ok()
                    .and_then(|txt| iface_owner(&txt))
                    .and_then(|ips| {
                        ips.into_iter().find_map(|ip| {
                            hosts
                                .iter()
                                .find(|(d, a)| *a == ip && configured.contains(d) && wan(d))
                                .map(|(d, _)| d.clone())
                        })
                    });
                trace.wan_verified(iface, device.is_some());
                device
            });
            if let Some(d) = device {
                add(&mut out, Some(addr), d, hosts);
            }
        }
        trace.step(
            "native.dns",
            &format!(
                "DHCP/PPP DNS-записей: {records}; принято после проверки WAN и адресов: {}",
                out.len()
            ),
        );
    }
    let authoritative = !out.is_empty();
    let mut evidence = Evidence {
        peers: out,
        history: Vec::new(),
        candidates: Vec::new(),
        wan_key: String::new(),
        authoritative,
        inform: InformEvidence {
            local: local_v4(hosts),
            ..InformEvidence::default()
        },
        inform_authoritative: authoritative,
        inform_candidates: Vec::new(),
        hosts: Vec::new(),
        fresh: Vec::new(),
        error: known_error.get().map(io::Error::from),
    };
    if !evidence.peers.is_empty() {
        return Ok(evidence);
    }

    let started = Instant::now();
    let routes = run.run_bounded(
        "ip",
        &["-4", "route", "show", "table", "main", "default"],
        deadline,
        128 << 10,
    );
    let owner = routes
        .as_ref()
        .ok()
        .and_then(|routes| Wan::read(routes, configured, hosts));
    trace.timed(
        "wan.default",
        &format!(
            "Таблица main: прочитана={}; принадлежность WAN подтверждена={}",
            routes.is_ok(),
            owner.is_some()
        ),
        started.elapsed(),
    );
    routes?;
    let Some(wan) = owner else {
        evidence.history = retained
            .iter()
            .cloned()
            .map(|mut lease| {
                lease.current = false;
                lease
            })
            .collect();
        return Ok(evidence);
    };
    let before = if wan.devices.iter().any(|device| super::ppp::device(device)) {
        read("show interface").ok()
    } else {
        None
    };
    let log = read("show log").ok();
    let clock = log
        .as_ref()
        .and_then(|_| run.run("date", &["+%Y-%m-%dT%H:%M:%S%z"], deadline).ok())
        .and_then(|raw| super::leases::parse_clock(&raw));
    let clock_at = Instant::now();
    let interfaces = if before.is_some() || known_error.get().is_none() {
        read("show interface").ok()
    } else {
        None
    };
    if let (Some(log), Some(clock), Some(before), Some(after)) = (
        log.as_deref(),
        clock,
        before.as_deref(),
        interfaces.as_deref(),
    ) {
        let active = |s| super::ppp::active(s, hosts, configured, &wan.devices);
        let before = active(before);
        let after = active(after);
        let verified = super::ppp::current(log, clock, &before, &after);
        trace.step(
            "native.ppp",
            &format!(
                "Подтверждённых PPPoE WAN: {}; адресов DNS текущего IPCP: {}",
                after.len(),
                verified.len()
            ),
        );
        for (device, ip) in verified {
            add(
                &mut evidence.peers,
                Some(SocketAddr::new(ip.into(), 53)),
                device,
                hosts,
            );
        }
    }

    let device_for = |client: Ipv4Addr| -> Option<&str> {
        let mut owners = hosts
            .iter()
            .filter(|(dev, ip)| wan.devices.contains(dev) && *ip == IpAddr::from(client));
        let (device, _) = owners.next()?;
        (!owners.any(|(other, _)| other != device)).then_some(device.as_str())
    };
    let mut statuses = HashMap::new();
    let mut verifies = |iface: &str, client: Ipv4Addr, fresh: bool| -> bool {
        let verified = statuses
            .entry(iface.to_owned())
            .or_insert_with(|| {
                let cmd = format!("show interface {iface}");
                let output = if fresh {
                    read(&cmd)
                } else {
                    let started = Instant::now();
                    let output = run.run_bounded("ndmc", &["-c", &cmd], deadline, 128 << 10);
                    trace.native_command(
                        &cmd,
                        output
                            .as_ref()
                            .is_ok_and(|text| !super::renew::native_error(text)),
                        started.elapsed(),
                    );
                    output
                };
                output
                    .ok()
                    .filter(|txt| !super::renew::native_error(txt))
                    .and_then(|txt| iface_owner(&txt))
            })
            .as_ref()
            .is_some_and(|addresses| addresses.contains(&client.into()));
        trace.wan_verified(iface, verified);
        verified
    };
    let mut retained: Vec<_> = retained
        .iter()
        .filter(|lease| lease.key == wan.key && lease.expires > clock_at)
        .cloned()
        .collect();
    for lease in &mut retained {
        if lease.at.is_none() {
            lease.at = clock.and_then(|now| super::leases::observed_at(&lease.stamp, now));
        }
        lease.current = device_for(lease.client).is_some_and(|device| {
            if (lease.bound && lease.peers.iter().any(|peer| peer.device != device))
                || !verifies(&lease.iface, lease.client, false)
            {
                return false;
            }
            for peer in &mut lease.peers {
                if !lease.bound {
                    peer.device = device.to_owned();
                }
            }
            lease.bound = true;
            true
        });
    }
    let server_is_remote = |server: Ipv4Addr, client: Ipv4Addr| {
        usable(server.into())
            && server != client
            && !hosts.iter().any(|(_, ip)| ip.to_canonical() == server)
    };
    let ack_records = log
        .as_deref()
        .map_or_else(Vec::new, super::leases::ack_records);
    let records = ack_records.len();
    let mut accepted = 0;
    if log.is_some() {
        trace.step(
            "native.leases",
            &format!("Связанных DHCP ACK в журнале: {records}"),
        );
    }
    for ack in ack_records {
        let Some(device) = device_for(ack.client) else {
            continue;
        };
        let at = clock.and_then(|clock| super::leases::observed_at(&ack.stamp, clock));
        if retained.iter().any(|old| {
            old.current && old.client == ack.client && {
                old.at.zip(at).is_some_and(|(old, at)| old > at)
                    || at.is_none() && old.observed_at.is_some()
            }
        }) || !verifies(&ack.iface, ack.client, true)
        {
            continue;
        }
        if let Some(server) = ack
            .server
            .filter(|server| server_is_remote(*server, ack.client))
        {
            if at.is_some() || ack.valid_stamp() {
                evidence.inform.ring.push(KnownTarget {
                    iface: ack.iface.clone(),
                    wan_key: wan.key.clone(),
                    client: ack.client,
                    server,
                    stamp: ack.stamp.clone(),
                    observed_at_epoch: at.map(|at| at.unix_timestamp()),
                });
            }
        }
        let Some(lease) = clock.and_then(|clock| ack.lease(clock)) else {
            continue;
        };
        let expires = clock_at + lease.remaining;
        let peers = lease_peers(lease.servers, device, hosts, expires);
        if !peers.is_empty() {
            accepted += 1;
            if accepted <= 8 {
                let at = lease
                    .at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                trace.step(
                    "native.log.lease",
                    &format!(
                        "{}: ACK={at}; lease={} с; остаток={} с; DNS={}",
                        lease.iface,
                        lease.lease_seconds,
                        lease.remaining.as_secs(),
                        peers.len()
                    ),
                );
            }
            evidence.fresh.push((lease.iface.clone(), lease.at));
            let known = retained.iter().find(|old| {
                old.iface == lease.iface && old.client == lease.client && old.at == Some(lease.at)
            });
            let expires = known.map_or(expires, |old| expires.min(old.expires));
            retained.retain(|old| old.iface != lease.iface);
            retained.push(History {
                key: wan.key.clone(),
                iface: lease.iface,
                client: lease.client,
                at: Some(lease.at),
                stamp: lease.stamp,
                lease_seconds: lease.lease_seconds,
                observed_at: None,
                expires,
                peers,
                bound: true,
                current: true,
            });
        }
    }
    if log.is_some() {
        trace.step("native.log.summary", &format!("Журнал: последних ACK={records}; подтверждённых аренд с DNS={accepted}; время проверено={}", clock.is_some()));
    }
    for lease in &mut retained {
        lease.peers.retain(|peer| {
            !hosts
                .iter()
                .any(|(_, ip)| ip.to_canonical() == peer.addr.ip())
        });
        for peer in &mut lease.peers {
            peer.expires = Some(lease.expires);
        }
    }
    retained.retain(|lease| !lease.peers.is_empty());
    if retained.len() > 32 {
        retained.sort_by_key(|lease| std::cmp::Reverse(lease.at));
        retained.truncate(32);
    }
    evidence.history = retained;
    if known_error.get().is_none() {
        if let Some(interfaces) = interfaces {
            evidence.candidates = wan.candidates(&interfaces, hosts);
        }
    }
    evidence.inform_candidates = evidence.candidates.clone();
    for hint in known.iter().take(8).chain(&evidence.inform.ring) {
        if hint.wan_key != wan.key
            || !native(&hint.iface)
            || !server_is_remote(hint.server, hint.client)
        {
            continue;
        }
        let owner = evidence
            .candidates
            .iter()
            .find(|owner| owner.client == hint.client);
        if let Some(owner) = owner
            .filter(|owner| owner.iface != hint.iface && verifies(&hint.iface, hint.client, false))
        {
            let alias = Candidate {
                iface: hint.iface.clone(),
                ..owner.clone()
            };
            if !evidence.inform_candidates.contains(&alias) {
                evidence.inform_candidates.push(alias);
            }
        }
    }
    evidence.inform.restored = known
        .iter()
        .take(8)
        .filter(|hint| {
            hint.wan_key == wan.key
                && server_is_remote(hint.server, hint.client)
                && evidence
                    .inform_candidates
                    .iter()
                    .any(|owner| owner.iface == hint.iface && owner.client == hint.client)
        })
        .cloned()
        .map(|mut hint| {
            if hint.observed_at_epoch.is_none() {
                hint.observed_at_epoch = clock
                    .and_then(|clock| super::leases::observed_at(&hint.stamp, clock))
                    .map(|at| at.unix_timestamp());
            }
            hint
        })
        .collect();
    evidence.inform.router_now = clock;
    evidence.inform.wan_ips = hosts
        .iter()
        .filter_map(|(device, ip)| match ip {
            IpAddr::V4(ip) if configured.contains(device) => Some(*ip),
            _ => None,
        })
        .collect();
    evidence.wan_key = wan.key;
    evidence.hosts = hosts.to_vec();
    evidence.error = known_error.get().map(io::Error::from);
    Ok(evidence)
}

#[cfg(test)]
fn collect(
    run: &dyn Runner,
    openwrt: bool,
    configured: &[String],
    hosts: &[(String, IpAddr)],
    retained: &[History],
) -> io::Result<Evidence> {
    collect_with_inform(
        run,
        openwrt,
        configured,
        hosts,
        Query {
            retained,
            known: &[],
            deadline: Instant::now() + Duration::from_secs(2),
            trace: &Trace::default(),
        },
    )
}

#[cfg(test)]
pub(super) fn discover(
    run: &dyn Runner,
    openwrt: bool,
    configured: &[String],
    hosts: &[(String, IpAddr)],
) -> io::Result<Vec<Peer>> {
    collect(run, openwrt, configured, hosts, &[])?
        .finish(None)
        .0
}

impl Source for Firmware {
    fn read(&self, retained: &[History]) -> io::Result<Evidence> {
        self.read_with_inform(retained, &[], Instant::now() + Duration::from_secs(2))
    }

    fn read_with_inform(
        &self,
        retained: &[History],
        known: &[KnownTarget],
        deadline: Instant,
    ) -> io::Result<Evidence> {
        self.read_traced(retained, known, deadline, &Trace::default())
    }

    fn read_traced(
        &self,
        retained: &[History],
        known: &[KnownTarget],
        deadline: Instant,
        trace: &Trace,
    ) -> io::Result<Evidence> {
        let hosts = lan::addresses()?;
        let mut evidence = collect_with_inform(
            &System,
            Path::new("/etc/openwrt_release").is_file(),
            &self.0,
            &hosts,
            Query {
                retained,
                known,
                deadline,
                trace,
            },
        )?;
        if !evidence.inform_candidates.is_empty() {
            if let Ok(live) = lan::addresses() {
                evidence.bind_inform(&live, observer::link_identity);
            } else {
                // A failed second link read disables active target approval.
                // Existing verified firmware/PPP lease discovery can still stand.
                evidence.inform.ring.clear();
                evidence.inform.restored.clear();
            }
        }
        Ok(evidence)
    }

    fn confirm_inform(&self, expected: &InformWan, deadline: Instant) -> bool {
        if Path::new("/etc/openwrt_release").is_file() {
            return false;
        }
        confirm_inform_with(
            &System,
            &self.0,
            lan::addresses,
            expected,
            deadline,
            observer::link_identity,
        )
    }

    fn target(&self, evidence: &Evidence, previous: Option<&Candidate>) -> Option<Target> {
        let candidate = evidence
            .candidates
            .iter()
            .find(|c| previous.is_some_and(|old| old.device == c.device && old.client == c.client))
            .or_else(|| evidence.candidates.first())?;
        let (index, mac) = observer::link_identity(&candidate.device).ok()?;
        let owned = lan::addresses()
            .ok()?
            .iter()
            .any(|(device, ip)| *device == candidate.device && *ip == candidate.client);
        owned.then(|| Target {
            wan_key: evidence.wan_key.clone(),
            candidate: candidate.clone(),
            index,
            mac,
        })
    }
}
