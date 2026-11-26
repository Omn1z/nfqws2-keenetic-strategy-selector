use super::super::Kernel;
use super::{err, plan, Routing, Value, Zone};
use std::{io, net::SocketAddr};

/// Go synthesizes this IPv4 blanket for an implicit full profile with a
/// saved connection reserve. Keep it out of the persisted zone document.
pub(in crate::kernel) fn zone(doc: &Value, policy: &Routing) -> Option<Zone> {
    if policy.mode != "full" || !policy.zones.is_empty() || policy.sni_routing {
        return None;
    }
    let rows = doc["servers"].as_array()?;
    if rows.len() != 2 || rows.iter().any(|row| !literal_direct(row)) {
        return None;
    }
    let mut active = rows
        .iter()
        .filter(|row| row["config"]["routing"]["active"] == true);
    let owner = active.next()?;
    if active.next().is_some()
        || owner["config"]["enabled"] != true
        || owner["config"]["client"]["enabled"] != true
    {
        return None;
    }
    let id = owner["id"].as_str()?;
    let [reserve] = owner["config"]["client"]["fallback_tunnel_ids"]
        .as_array()?
        .as_slice()
    else {
        return None;
    };
    let reserve = reserve.as_str()?;
    let holder = rows
        .iter()
        .find(|row| row["id"] == reserve && row["id"] != id)?;
    let onward = &holder["config"]["client"]["fallback_tunnel_ids"];
    if !onward.is_null() && !onward.as_array().is_some_and(Vec::is_empty) {
        return None;
    }
    Some(implicit_zone(id, reserve))
}

fn implicit_zone(id: &str, reserve: &str) -> Zone {
    Zone {
        name: "Весь трафик".into(),
        tunnel_id: id.to_owned(),
        fallback_tunnel_ids: vec![reserve.to_owned()],
        route: "tunnel".into(),
        domains: vec!["*".into()],
        enabled: true,
        ..Zone::default()
    }
}

pub(in crate::kernel) fn native_draft(doc: &Value, policy: &Routing) -> Option<Zone> {
    if policy.mode != "full" || !policy.zones.is_empty() || policy.sni_routing {
        return None;
    }
    let [owner, reserve] = nfqws2_awg_profile::native_full_reserve_draft(doc)?;
    Some(implicit_zone(
        owner["id"].as_str()?,
        reserve["id"].as_str()?,
    ))
}

fn literal_direct(row: &Value) -> bool {
    let cfg = &row["config"];
    let client = &cfg["client"];
    let backups = &client["endpoint_backups"];
    row["applied_config"].is_null()
        && cfg["install"] == "imported"
        && cfg["routing"]["mode"] == "full"
        && client["standby"] != true
        && client["double_tunnel_id"]
            .as_str()
            .is_none_or(str::is_empty)
        && matches!(
            client["double_tunnel_mode"].as_str(),
            None | Some("" | "off")
        )
        && (backups.is_null() || backups.as_array().is_some_and(Vec::is_empty))
        && cfg["endpoint"]
            .as_str()
            .and_then(|raw| raw.parse::<SocketAddr>().ok())
            .and_then(crate::kernel::mtu_edit::canonical_socket)
            .is_some_and(|endpoint| endpoint.is_ipv4())
}

pub(super) fn carrier(plan: &plan::Plan) -> Option<&str> {
    let mut flows = plan.flows();
    let (selector, primary) = flows.next()?;
    if !plan.go_ipv4
        || plan.full_endpoints.is_none()
        || selector.dest != plan::Family::V4.any()
        || flows.next().is_some()
    {
        return None;
    }
    let iface = plan.effective(selector, primary)?;
    Some(plan.targets.get(iface)?.id.as_str())
}

pub(in crate::kernel) fn reserve_with_separate_intent<'a>(
    doc: &Value,
    plan: &'a plan::Plan,
) -> Option<&'a str> {
    if !plan.go_ipv4 || plan.full_endpoints.is_none() || plan.legacy_full.is_some() {
        return None;
    }
    let [(selector, candidates)] = plan.reserves.as_slice() else {
        return None;
    };
    let [reserve] = candidates.as_slice() else {
        return None;
    };
    let policy = crate::policy::current(doc).ok()?;
    let implicit = zone(doc, &policy).or_else(|| native_draft(doc, &policy))?;
    let owner = plan
        .prefixes
        .get(&selector.dest)
        .and_then(|iface| plan.targets.get(iface))?;
    let target = plan.targets.get(reserve)?;
    (selector.dest == plan::Family::V4.any()
        && owner.id == implicit.tunnel_id
        && implicit.fallback_tunnel_ids == [target.id.as_str()])
    .then_some(target.id.as_str())
}

fn invalid_ipv6() -> io::Error {
    err("активная политика IPv6 не соответствует AWG2_MULTI")
}

#[derive(Eq, PartialEq)]
pub(super) struct LegacyIpv6Residue {
    priority: u16,
    default_present: bool,
    wan: String,
}

fn reserved_row(line: &str) -> bool {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    fields.windows(2).any(|fields| {
        matches!(fields[0], "lookup" | "table")
            && fields[1]
                .parse::<u16>()
                .is_ok_and(|table| matches!(table, 900..=964 | 998 | 17842..=17907 | 18000..=18128))
    })
}

fn residue_default(row: &str, iface: &str) -> bool {
    let fields: Vec<_> = row.split_ascii_whitespace().collect();
    let ["default", "dev", dev, attrs @ ..] = fields.as_slice() else {
        return false;
    };
    let mut parsed = std::collections::BTreeSet::new();
    let mut pairs = attrs.chunks_exact(2);
    *dev == iface
        && pairs.all(|pair| {
            parsed.insert(pair[0])
                && matches!(
                    pair,
                    ["table", "998"]
                        | ["metric", "1024"]
                        | ["proto", "boot" | "3"]
                        | ["pref", "medium" | "0"]
                )
        })
        && pairs.remainder().is_empty()
        && parsed.contains("table")
        && parsed.contains("metric")
}

fn installs_packet_mark(rule: &str) -> bool {
    let fields: Vec<_> = rule.split_ascii_whitespace().collect();
    match fields.windows(2).find_map(|fields| {
        matches!(fields[0], "-j" | "--jump" | "-g" | "--goto").then_some(fields[1])
    }) {
        Some("MARK") => fields
            .windows(2)
            .find_map(|fields| {
                matches!(
                    fields[0],
                    "--set-xmark" | "--set-mark" | "--or-mark" | "--xor-mark"
                )
                .then_some(fields[1].split('/').next().unwrap_or_default())
            })
            .and_then(|bits| {
                bits.strip_prefix("0x").map_or_else(
                    || bits.parse().ok(),
                    |hex| u32::from_str_radix(hex, 16).ok(),
                )
            })
            .is_none_or(|bits: u32| bits & 0x1000_0000 != 0),
        Some("CONNMARK" | "HMARK" | "NFQUEUE" | "QUEUE") => true,
        _ => false,
    }
}

fn nft_packet_mark_writer(rule: &Value) -> bool {
    matches!(
        rule["family"].as_str(),
        Some("ip6" | "inet" | "bridge" | "netdev")
    ) && rule["expr"].as_array().is_none_or(|exprs| {
        exprs.iter().any(|expr| {
            expr["mangle"]["key"]["meta"]["key"] == "mark" || expr.get("queue").is_some()
        })
    })
}

fn verify_inert(k: &Kernel<'_>) -> io::Result<String> {
    if k.call("ip6tables-save", &[])?
        .lines()
        .any(installs_packet_mark)
    {
        return Err(invalid_ipv6());
    }
    let nft = k.call("sh", &["-c", "if command -v nft >/dev/null 2>&1; then nft -j list ruleset; elif [ -d /sys/module/nf_tables ]; then exit 1; fi"])?;
    if !nft.is_empty() {
        let nft: Value = serde_json::from_str(&nft).map_err(|_| invalid_ipv6())?;
        if nft["nftables"].as_array().is_none_or(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("rule"))
                .any(nft_packet_mark_writer)
        }) {
            return Err(invalid_ipv6());
        }
    }
    let route = k.call("ip", &["-6", "route", "get", "2620:fe::fe"])?;
    let fields: Vec<_> = route.split_ascii_whitespace().collect();
    let wan = fields
        .windows(2)
        .find_map(|pair| (pair[0] == "dev").then_some(pair[1]));
    wan.filter(|dev| plan::LegacyFull::valid_wan(dev))
        .map(str::to_owned)
        .ok_or_else(invalid_ipv6)
}

fn inspect_ipv6(
    k: &Kernel<'_>,
    source: Option<(&Value, &Zone)>,
    reject: Option<&str>,
) -> io::Result<Option<LegacyIpv6Residue>> {
    if !k.ipv6_stack()? {
        return if reject.is_none() {
            Ok(None)
        } else {
            Err(invalid_ipv6())
        };
    }
    let rules = k.listing(plan::Family::V6, &["rule", "show"])?;
    let routes = k.listing(plan::Family::V6, &["route", "show", "table", "all"])?;
    let rules: Vec<_> = rules.lines().filter(|line| reserved_row(line)).collect();
    let routes: Vec<_> = routes.lines().filter(|line| reserved_row(line)).collect();
    if source.is_none() && (!rules.is_empty() || !routes.is_empty()) {
        return Err(invalid_ipv6());
    }
    let reject_spec = reject.and_then(|wan| {
        crate::kernel::Object::LegacyV6Reject(wan.to_owned())
            .xtables()
            .map(|(_, _, arguments)| arguments)
    });
    let mut found_reject = false;
    for table in ["mangle", "filter", "nat"] {
        let rules = k.call("ip6tables", &["-w", "-t", table, "-S"])?;
        let first_forward = rules.lines().find(|line| line.starts_with("-A FORWARD "));
        for line in rules.lines() {
            if !found_reject
                && table == "filter"
                && Some(line) == first_forward
                && reject_spec.as_ref().is_some_and(|arguments| {
                    line.split_ascii_whitespace()
                        .map(|word| word.trim_matches('"'))
                        .eq(["-A", "FORWARD"]
                            .into_iter()
                            .chain(arguments.iter().map(String::as_str)))
                })
            {
                found_reject = true;
                continue;
            }
            if line.contains("AWG2_")
                || line.contains("nfqws2-awg2")
                || line.contains("awg2-v6")
                || line.contains("n2s-awg-")
            {
                return Err(invalid_ipv6());
            }
        }
    }
    if reject.is_some() != found_reject {
        return Err(invalid_ipv6());
    }
    if rules.is_empty() && routes.is_empty() {
        return Ok(None);
    }
    let (doc, zone) = source.ok_or_else(invalid_ipv6)?;
    let rows = doc["servers"].as_array().ok_or_else(invalid_ipv6)?;
    let (_, iface, _) = plan::profile(doc, rows, &zone.tunnel_id)?;
    let [rule] = rules.as_slice() else {
        return Err(invalid_ipv6());
    };
    let fields: Vec<_> = rule.split_ascii_whitespace().collect();
    let [priority, "from", "all", "fwmark", "0x10000000/0x10000000", "lookup", "998"] =
        fields.as_slice()
    else {
        return Err(invalid_ipv6());
    };
    let priority = priority
        .strip_suffix(':')
        .and_then(|n| n.parse().ok())
        .filter(|p: &u16| *p > 0 && *p < 32766)
        .ok_or_else(invalid_ipv6)?;
    let default_present = match routes.as_slice() {
        [route] if residue_default(route, &iface) => true,
        [] if !crate::kernel::routed_disable::link_names(k)?.contains(&iface) => false,
        _ => return Err(invalid_ipv6()),
    };
    Ok(Some(LegacyIpv6Residue {
        priority,
        default_present,
        wan: verify_inert(k)?,
    }))
}

/// Only the live source check can recognize inert remnants left by Go's
/// ordinary Apply. The source shutdown still owns and removes those objects.
pub(super) fn source_ipv6(
    k: &Kernel<'_>,
    doc: &Value,
    zone: &Zone,
) -> io::Result<Option<LegacyIpv6Residue>> {
    inspect_ipv6(k, Some((doc, zone)), None)
}

/// Native trial and recovery require the old IPv6 objects to be absent.
pub(in crate::kernel) fn verify_ipv6(k: &Kernel<'_>) -> io::Result<()> {
    verify_ipv6_with_owned_reject(k, None)
}

pub(in crate::kernel) fn verify_ipv6_with_owned_reject(
    k: &Kernel<'_>,
    reject: Option<&str>,
) -> io::Result<()> {
    inspect_ipv6(k, None, reject).map(|_| ())
}
