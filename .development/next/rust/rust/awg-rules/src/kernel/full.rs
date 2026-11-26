//! Management, transport and fail-closed paths for a global default tunnel.
use super::{
    inventory::{Kernel, Object},
    plan::{Family, Plan, Prefix},
};
use crate::model::err;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    sync::LazyLock,
};

// Keep local, non-routable and CGNAT traffic on the router's existing path.
// A separate main-table lookup also exempts current and future connected
// prefixes, including a delegated public IPv6 LAN or a public WAN gateway.
static PRIVATE: LazyLock<Vec<Prefix>> = LazyLock::new(|| {
    "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 ::/96 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8"
        .split_ascii_whitespace().map(|s| s.parse().unwrap()).collect()
});
pub(super) fn excluded_v4() -> impl Iterator<Item = Prefix> {
    PRIVATE.iter().copied().filter(|p| p.family() == Family::V4)
}
const TABLE: &str = "17842";
const PROTO: &str = "242";
const FENCE_METRIC: &str = "32000";

// These paired selectors belong to the nested engine, not to the payload
// policy. Only its exact socket mark can match. Mask bit 0x20000000 is set
// there and must be clear for our full-tunnel lookup. Never mutate the pair.
pub(super) fn socket_pairs<'a>(
    listing: &'a str,
    expected: &BTreeMap<u32, u32>,
) -> io::Result<BTreeSet<&'a str>> {
    let mut pairs = BTreeMap::new();
    for line in listing.lines().filter(|_| !expected.is_empty()) {
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        let [priority @ ("60:" | "61:"), "from", "all", "fwmark", raw, action @ ..] =
            words.as_slice()
        else {
            continue;
        };
        let raw = raw.strip_suffix("/0xffffffff").unwrap_or(raw);
        let mark = raw
            .strip_prefix("0x")
            .and_then(|v| u32::from_str_radix(v, 16).ok());
        let Some((mark, table)) = mark.and_then(|v| expected.get_key_value(&v)) else {
            continue;
        };
        let index = match (*priority, action) {
            ("60:", ["lookup" | "table", t]) if t.parse::<u32>().ok() == Some(*table) => 0,
            (
                "61:",
                ["prohibit" | "reject" | "8"]
                | ["lookup", "main" | "254", "prohibit" | "reject" | "8"],
            ) => 1,
            _ => return Err(err("изменилась пара правил сокета вложенного AWG")),
        };
        let pair = pairs.entry(*mark).or_insert([None; 2]);
        if pair[index].replace(line).is_some() {
            return Err(err("повторное правило сокета вложенного AWG"));
        }
    }
    let mut result = BTreeSet::new();
    for pair in pairs.into_values() {
        let [Some(lookup), Some(guard)] = pair else {
            return Err(err("неполная пара правил сокета вложенного AWG"));
        };
        result.extend([lookup, guard]);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Guard {
    Main(Family),
    SourceMain(Prefix),
    SourceLookup(Prefix),
    Throw(Prefix),
    Fence(Family),
}
impl Guard {
    pub fn family(self) -> Family {
        match self {
            Self::Main(f) | Self::Fence(f) => f,
            Self::Throw(p) | Self::SourceMain(p) | Self::SourceLookup(p) => p.family(),
        }
    }
    pub fn mutate(self, k: &Kernel<'_>, add: bool) -> io::Result<()> {
        let command = if add { "add" } else { "del" };
        let af = self.family().flag();
        match self {
            Self::SourceMain(src) => k.call(
                "ip",
                &[
                    af,
                    "rule",
                    command,
                    "pref",
                    "67",
                    "from",
                    &src.to_string(),
                    "lookup",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            )?,
            Self::SourceLookup(src) => k.call(
                "ip",
                &[
                    af,
                    "rule",
                    command,
                    "pref",
                    "68",
                    "from",
                    &src.to_string(),
                    "fwmark",
                    "0/0x20000000",
                    "table",
                    TABLE,
                ],
            )?,
            Self::Main(_) => k.call(
                "ip",
                &[
                    af,
                    "rule",
                    command,
                    "pref",
                    "67",
                    "lookup",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            )?,
            Self::Throw(p) => k.call(
                "ip",
                &[
                    af,
                    "route",
                    command,
                    "throw",
                    &p.to_string(),
                    "table",
                    TABLE,
                    "proto",
                    PROTO,
                ],
            )?,
            Self::Fence(_) => k.call(
                "ip",
                &[
                    af,
                    "route",
                    command,
                    "unreachable",
                    "default",
                    "metric",
                    FENCE_METRIC,
                    "table",
                    TABLE,
                    "proto",
                    PROTO,
                ],
            )?,
        };
        Ok(())
    }
}
pub(super) fn objects(plan: &Plan, endpoints: &BTreeSet<IpAddr>, out: &mut BTreeSet<Object>) {
    for net in PRIVATE
        .iter()
        .copied()
        .chain(endpoints.iter().copied().map(Prefix::host))
        .chain(plan.full_direct.iter().copied())
        .filter(|p| plan.uses_family(p.family()))
    {
        out.insert(Object::FullGuard(Guard::Throw(net)));
    }
    for (selector, iface) in plan.flows() {
        let f = selector.dest.family();
        if plan.full_sources.is_empty() {
            out.insert(Object::FullGuard(Guard::Main(f)));
            out.insert(Object::PackedLookup(f));
        } else {
            for &src in &plan.full_sources {
                out.insert(Object::FullGuard(Guard::SourceMain(src)));
                out.insert(Object::FullGuard(Guard::SourceLookup(src)));
            }
        }
        // The lookup stays through outages, so the unreachable default in the
        // same table prevents WAN leakage until an authorized peer returns.
        if plan.killswitch || (f == Family::V6 && plan.effective(selector, iface).is_none()) {
            out.insert(Object::FullGuard(Guard::Fence(f)));
        }
    }
}
pub(super) fn route(family: Family, words: &[&str]) -> io::Result<Option<Guard>> {
    let Some((kind, args)) = words.split_first() else {
        return Ok(None);
    };
    if !matches!(*kind, "throw" | "9" | "unreachable" | "7") {
        return Ok(None);
    }
    let Some((dest, rest)) = args.split_first() else {
        return Err(err("неизвестная защита в таблице маршрутизации AWG"));
    };
    let guard = match *kind {
        "throw" | "9" => Guard::Throw(dest.parse()?),
        _ if *dest == "default" => Guard::Fence(family),
        _ => return Err(err("чужая защита в таблице AWG")),
    };
    let mut labels = BTreeSet::new();
    let mut attrs = rest.chunks_exact(2);
    if !attrs.all(|p| {
        labels.insert(p[0])
            && match p {
                ["table", TABLE] | ["proto", PROTO] => true,
                ["metric", FENCE_METRIC] => matches!(guard, Guard::Fence(_)),
                ["metric", "1024"] => family == Family::V6 && matches!(guard, Guard::Throw(_)),
                // IPv6 displays RTN_THROW and RTN_UNREACHABLE against loopback.
                ["dev", "lo"] => family == Family::V6,
                ["pref", "medium" | "0"] => family == Family::V6,
                ["scope", "link" | "253"] => matches!(guard, Guard::Throw(_)),
                _ => false,
            }
    }) || !attrs.remainder().is_empty()
        || !labels.contains("proto")
        || !labels.contains("table")
        || matches!(guard, Guard::Fence(_)) && !labels.contains("metric")
    {
        return Err(err("чужой маршрут в таблице защиты полного туннеля"));
    }
    Ok(Some(guard))
}
pub(super) fn main_rule(words: &[&str], family: Family) -> Option<Guard> {
    let ["67:", "from", src, "lookup", "main" | "254", "suppress_prefixlength", "0"] = words else {
        return None;
    };
    if *src == "all" {
        return Some(Guard::Main(family));
    }
    src.parse::<Prefix>()
        .ok()
        .filter(|p| !p.any() && p.family() == family)
        .map(Guard::SourceMain)
}

pub(super) fn source_probes(
    k: &Kernel<'_>,
    plan: &Plan,
    family: Family,
) -> io::Result<Vec<(IpAddr, Option<String>)>> {
    if plan.full_sources.is_empty() {
        return Ok(Vec::new());
    }
    let addrs = k.call("ip", &["-o", family.flag(), "addr", "show"])?;
    let mut lan = Vec::new();
    for row in addrs.lines() {
        let words: Vec<_> = row.split_ascii_whitespace().collect();
        if let [_, dev, label, addr, ..] = words.as_slice() {
            let dev = dev.split('@').next().unwrap_or(dev);
            if *label != family.inet() || dev == "lo" || plan.targets.contains_key(dev) {
                continue;
            }
            if let Some((ip, net)) = addr
                .split('/')
                .next()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .zip(addr.parse::<Prefix>().ok())
            {
                lan.push((dev.to_owned(), ip, net));
            }
        }
    }
    plan.full_sources
        .iter()
        .map(|src| {
            lan.iter()
                .find_map(|(name, ip, net)| {
                    src.forwarded_sample(*net, *ip)
                        .map(|p| (p, Some(name.clone())))
                })
                .or_else(|| {
                    lan.iter()
                        .find(|(_, ip, _)| src.contains(*ip))
                        .map(|(_, ip, _)| (*ip, None))
                })
                .ok_or_else(|| {
                    err("не найден интерфейс источника для подтверждения маршрута по умолчанию")
                })
        })
        .collect()
}
pub(super) fn verify(k: &Kernel<'_>, plan: &Plan, endpoints: &BTreeSet<IpAddr>) -> io::Result<()> {
    for (sel, primary) in plan.flows() {
        let f = sel.dest.family();
        let main = k.listing(f, &["route", "show", "table", "main"])?;
        let mut exceptions: Vec<_> = plan.full_direct.iter().copied().collect();
        for line in main.lines() {
            let mut words = line.split_ascii_whitespace();
            let mut dest = words.next().unwrap_or_default();
            if matches!(
                dest,
                "unicast" | "blackhole" | "unreachable" | "prohibit" | "throw"
            ) {
                dest = words.next().unwrap_or_default();
            }
            if dest == "default" {
                continue;
            }
            let p: Prefix = dest.parse()?;
            if !p.any() {
                exceptions.push(p);
            }
        }
        let probes = match f {
            Family::V4 => ["1.1.1.1", "9.9.9.9", "208.67.222.222"],
            Family::V6 => [
                "2606:4700:4700::1111",
                "2620:fe::fe",
                "2001:4860:4860::8888",
            ],
        };
        let probe = probes
            .into_iter()
            .find(|s| {
                let ip: IpAddr = s.parse().unwrap();
                !endpoints.contains(&ip) && !exceptions.iter().any(|p| p.contains(ip))
            })
            .ok_or_else(|| err("нет тестового назначения для проверки полного туннеля"))?;
        // FIB queries do not transmit test traffic. An unreachable default has
        // already been read back with its precise protocol and metric.
        let sources = source_probes(k, plan, f)?;
        let probes = if sources.is_empty() {
            vec![None]
        } else {
            sources.into_iter().map(Some).collect()
        };
        for src in probes {
            let mut args = vec![f.flag(), "route", "get", probe];
            let source;
            if let Some((ip, iface)) = &src {
                source = ip.to_string();
                args.extend(["from", source.as_str()]);
                if let Some(iface) = iface {
                    args.extend(["iif", iface.as_str()]);
                }
            }
            let path = k.call("ip", &args);
            match plan.effective(sel, primary) {
                Some(iface) => {
                    let path = path?;
                    if !path
                        .split_ascii_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .any(|w| w == ["dev", iface])
                    {
                        return Err(err("ядро не выбрало действующий полный туннель"));
                    }
                }
                None if (plan.killswitch || f == Family::V6) && path.is_ok() => {
                    return Err(err(
                        "ядро пропускает трафик при недоступном защищённом туннеле",
                    ))
                }
                None => (),
            }
        }
    }
    for endpoint in endpoints {
        let path = k.call(
            "ip",
            &[
                Family::of(*endpoint).flag(),
                "route",
                "get",
                &endpoint.to_string(),
            ],
        )?;
        let words: Vec<_> = path.split_ascii_whitespace().collect();
        if !words
            .windows(2)
            .any(|w| w[0] == "dev" && !plan.targets.contains_key(w[1]))
        {
            return Err(err("утрачен внешний маршрут до транспорта AWG"));
        }
    }
    Ok(())
}
