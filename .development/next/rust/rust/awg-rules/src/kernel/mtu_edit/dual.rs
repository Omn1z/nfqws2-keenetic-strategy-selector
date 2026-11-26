//! Keep a Go dual-stack blanket fenced until the new TUN can be probed.
use super::*;
use plan::{Family, LegacyFull};

pub(in super::super) fn dual_probe_phase(plan: &Plan, iface: &str) -> bool {
    let v6 = Family::V6.any();
    plan.legacy_full == Some(LegacyFull::Dual)
        && plan.probe_iface() == Some(iface)
        && plan.prefixes.get(&v6).is_some_and(|primary| {
            plan.effective(
                plan::Selector {
                    source: v6,
                    dest: v6,
                },
                primary,
            )
            .is_none()
        })
}

/// Authorize one fresh interface-bound IPv6 probe in the intermediate phase.
pub fn legacy_dual_probe_target(
    db: &Store,
    run: &dyn Runner,
) -> io::Result<Option<(String, SocketAddr)>> {
    let Some(edit) = read(db)? else {
        return Ok(None);
    };
    let j = Journal::read(db)?;
    if !edit
        .full_edit(&j)
        .is_some_and(|full| full.dual && full.staged)
        || !j.preparing.is_empty()
        || !dual_probe_phase(&j.installed, &edit.change.iface)
    {
        return Ok(None);
    }
    let doc = nfqws2_awg_profile::read(db)?;
    let proof = edit.proof(&doc, &j)?;
    let Some(endpoint) = proof.endpoint else {
        return Ok(None);
    };
    let k = kernel_for_transition(run, db, &j, &j.installed)?;
    if j.boot != boot_id(&k)?
        || k.inventory(&j.claims(), true)? != objects(&j.installed)
        || k.verify_probe_iface(&edit.change.iface).is_err()
    {
        return Ok(None);
    }
    Ok(Some((edit.change.iface, endpoint)))
}

/// The ordinary Go FORWARD reject may replace the temporary IPv6 fence
/// only when every non-LAN native IPv6 egress uses that guarded WAN.
pub(in super::super) fn legacy_dual_reject_wan(k: &Kernel<'_>, iface: &str) -> io::Result<String> {
    let wan = k.legacy_wan(false)?;
    let alternate = || err("не подтверждён единственный WAN для IPv6-защиты полного туннеля AWG");
    if !k.ipv6_stack()? {
        return Err(alternate());
    }
    for line in k
        .listing(Family::V6, &["rule", "show"])?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        match words.as_slice() {
            ["0:", "from", "all", "lookup", "local" | "255"]
            | ["32766:", "from", "all", "lookup", "main" | "254"]
            | ["32767:", "from", "all", "lookup", "default" | "253"]
            | ["67:", "from", "all", "lookup", "main" | "254", "suppress_prefixlength", "0"]
            | ["68:", "from", "all", "fwmark", "0/0x20000000" | "0x0/0x20000000", "lookup", "17842"] =>
                {}
            ["66:", "from", "all", "to", dest, "oif", device, "lookup", "17907"]
                if *device == iface && dest.trim_end_matches("/128") == inventory::PROBE_IP => {}
            _ => return Err(alternate()),
        }
    }
    for line in k
        .listing(Family::V6, &["route", "show", "table", "all"])?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        let after = |key| {
            words
                .windows(2)
                .find(|pair| pair[0] == key)
                .map(|pair| pair[1])
        };
        if after("table").is_some_and(|table| !matches!(table, "main" | "254" | "default" | "253"))
            || matches!(
                words[0],
                "unreachable" | "prohibit" | "throw" | "blackhole" | "7" | "8" | "9" | "6"
            )
        {
            continue;
        }
        let mut devices = words
            .windows(2)
            .filter(|pair| pair[0] == "dev")
            .map(|pair| pair[1])
            .peekable();
        let dest = if matches!(words[0], "unicast" | "1") {
            words.get(1).copied().unwrap_or("")
        } else {
            words[0]
        };
        let connected = !matches!(dest, "default" | "::/0")
            && !words.contains(&"via")
            && !words.contains(&"nexthop")
            && matches!(after("proto"), Some("kernel" | "2"));
        let link_local = dest
            .split('/')
            .next()
            .and_then(|ip| ip.parse::<std::net::Ipv6Addr>().ok())
            .is_some_and(|ip| ip.is_unicast_link_local());
        if devices.peek().is_none()
            || devices.any(|device| {
                device != wan
                    && !(connected
                        && (device == iface
                            || link_local
                            || super::super::valid_dns_bridge(device)))
            })
        {
            return Err(alternate());
        }
    }
    Ok(wan)
}
