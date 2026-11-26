use super::invalid;
use crate::dnsserver::{interface_records, live_addresses, native_wan, wan_defaults};
use nfqws2_config::{Platform, Resolver};
use nfqws2_router_command::{Runner, System};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    net::IpAddr,
    time::{Duration, Instant},
};
#[cfg(test)]
mod tests;

pub(super) fn literal(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 16
        && !matches!(s, "." | "..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

pub(super) fn wildcard(s: &str) -> bool {
    s.len() < 16
        && s.strip_suffix('+')
            .is_some_and(|prefix| prefix.is_empty() || literal(prefix))
}

fn selected(patterns: &[String], device: &str) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|s| s == device || wildcard(s) && device.starts_with(s.trim_end_matches('+')))
}

fn detect(
    run: &dyn Runner,
    platform: Platform,
    hosts: &[(String, IpAddr)],
    saved: &[String],
    current: &[String],
) -> io::Result<Vec<String>> {
    let until = Instant::now() + Duration::from_secs(3);
    let routes = run.run_bounded(
        "ip",
        &["-4", "route", "show", "table", "main", "default"],
        until,
        64 << 10,
    )?;
    let mut devices = wan_defaults(&routes);
    devices.retain(|name| {
        selected(saved, name)
            && selected(current, name)
            && hosts.iter().any(|(dev, ip)| dev == name && ip.is_ipv4())
    });
    if devices.is_empty() {
        return Ok(vec![]);
    }
    let mut found = BTreeSet::new();
    match platform {
        Platform::Entware => {
            let text = run.run_bounded("ndmc", &["-c", "show interface"], until, 1 << 20)?;
            found.extend(interface_records(&text, |name, fields| {
                let field = |key| fields.get(key).copied();
                if !native_wan(name)
                    || !native_wan(field("id")?)
                    || !matches!(
                        field("type")?,
                        "Ethernet" | "FastEthernet" | "GigabitEthernet" | "Vlan" | "PPPoE"
                    )
                    || field("global") != Some("yes")
                    || field("connected") != Some("yes")
                    || field("security-level") != Some("public")
                    || field("defaultgw") != Some("yes")
                {
                    return None;
                }
                let local = IpAddr::V4(field("address")?.parse().ok()?);
                let mut owners = hosts.iter().filter(|(_, ip)| *ip == local);
                let dev = &owners.next()?.0;
                (owners.all(|(other, _)| other == dev) && devices.contains(dev))
                    .then(|| dev.clone())
            }));
        }
        Platform::OpenWrt => {
            // Logical LAN and WAN can map to arbitrarily named firewall zones.
            // The active kernel default and the firewall must agree on the device.
            let (firewall, zone) = match run.run("fw4", &["-q", "network", "wan"], until) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    ("fw3", run.run("fw3", &["-q", "network", "wan"], until)?)
                }
                result => ("fw4", result?),
            };
            let lan = run.run(firewall, &["-q", "network", "lan"], until)?;
            if !literal(zone.trim()) || !literal(lan.trim()) || lan.trim() == zone.trim() {
                return Ok(vec![]);
            }
            for dev in devices {
                let owner = run.run(firewall, &["-q", "device", &dev], until);
                if owner.is_ok_and(|v| v.trim() == zone.trim()) {
                    found.insert(dev);
                }
            }
        }
    }
    Ok(found.into_iter().collect())
}

fn current_selectors(conf: &str, saved: &[String]) -> io::Result<Option<Vec<String>>> {
    let mut source = String::new();
    match File::open(conf) {
        Ok(f) => {
            f.take((1 << 20) + 1).read_to_string(&mut source)?;
            if source.len() > 1 << 20 {
                return Err(invalid("oversized ISP interface configuration"));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(saved.is_empty().then(Vec::new));
        }
        Err(e) => return Err(e),
    }
    // None also represents a shell expression. Disappearance or replacement
    // of an earlier literal wildcard cannot authorize the old interface.
    Ok(nfqws2_config::wan_interfaces_from_conf(&source)?
        .filter(|current| !current.is_empty() || saved.is_empty())
        .map(|mut current| {
            // The ordinary Go and Rust hooks select the literal interfaces
            // when a list mixes them with unsupported prefix expressions.
            if current.iter().any(|name| literal(name)) {
                current.retain(|name| literal(name));
            }
            current
        }))
}

pub(super) fn live(conf: &str, saved: &[String]) -> io::Result<Vec<String>> {
    let Some(current) = current_selectors(conf, saved)? else {
        return Ok(Vec::new());
    };
    detect(
        &System,
        Resolver::current().platform(),
        &live_addresses()?,
        saved,
        &current,
    )
}
