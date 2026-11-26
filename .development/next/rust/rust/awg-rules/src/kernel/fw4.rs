//! Put forwarding permission inside fw4's LAN zone. A verdict in a separate
//! iptables-nft base chain cannot override fw4's zone policy.
use super::{
    err,
    inventory::Kernel,
    mtu_edit::{Authority, Proof},
    plan::{self, Family, Selector},
    Object, Prefix,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    io,
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Rule {
    Nat,
    Forward(String),
    Clamp,
}
// fw4.parse_identifier(), additionally bounded by NFT_NAME_MAXLEN including
// the generated "forward_" prefix and terminating NUL.
pub(super) fn valid_zone(name: &str) -> bool {
    name.len() <= 247
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'.'))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
}
pub(super) fn forward_chain(zone: Option<&str>) -> String {
    format!("forward_{}", zone.unwrap_or("lan"))
}
pub(super) fn rules(zone: Option<&str>) -> [Rule; 3] {
    [Rule::Nat, Rule::Forward(forward_chain(zone)), Rule::Clamp]
}
const TAG: &str = r#"comment "n2s-awg-cidr""#;
#[derive(Debug)]
struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fw4: зона LAN или состав её правил изменились до записи")
    }
}
impl std::error::Error for Refused {}
pub(super) fn refused(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|cause| cause.is::<Refused>())
}

impl Rule {
    fn chain(&self) -> &str {
        match self {
            Self::Nat => "srcnat",
            Self::Forward(chain) => chain,
            Self::Clamp => "mangle_forward",
        }
    }
    fn body(&self, s: Selector, iface: &str) -> String {
        let af = if s.dest.family() == Family::V4 {
            "ip"
        } else {
            "ip6"
        };
        let addr = |p: Prefix| {
            let mut text = p.to_string();
            if text.ends_with("/32") && p.family() == Family::V4 || text.ends_with("/128") {
                text.truncate(text.rfind('/').unwrap());
            }
            text
        };
        let mut body = String::new();
        if !s.source.any() {
            write!(body, "{af} saddr {} ", addr(s.source)).unwrap();
        }
        let action = match self {
            Self::Nat => "masquerade",
            Self::Forward(_) => "accept",
            // The assignment only acts on packets carrying the TCP MSS option.
            Self::Clamp => "tcp option maxseg size set rt mtu",
        };
        write!(
            body,
            "{af} daddr {} oifname \"{iface}\" {action} {TAG}",
            addr(s.dest)
        )
        .unwrap();
        body
    }
}

pub(super) fn inventory(
    k: &Kernel<'_>,
    claims: &BTreeSet<Object>,
    proposed: &BTreeSet<Object>,
    strict: bool,
) -> io::Result<BTreeSet<Object>> {
    let mut expected = BTreeMap::new();
    for o in claims {
        if let Object::Native(s, iface, kind) = o {
            expected.insert((kind.chain(), kind.body(*s, iface)), o);
        }
    }
    let mut seen = BTreeSet::new();
    fn chains(set: &BTreeSet<Object>) -> BTreeSet<&str> {
        set.iter()
            .filter_map(|o| match o {
                Object::Native(_, _, kind) => Some(kind.chain()),
                _ => None,
            })
            .collect()
    }
    let needed = chains(proposed);
    for &chain in chains(claims).union(&needed) {
        let listing = match k.call("nft", &["-a", "list", "chain", "inet", "fw4", chain]) {
            Ok(listing) => listing,
            Err(_) if (!strict || !needed.contains(chain)) && chain_absent(k, chain)? => continue,
            Err(e) => {
                return Err(err(format!(
                    "AWG: не удалось прочитать цепочку inet fw4 {chain}: {e}"
                )))
            }
        };
        for line in listing.lines().filter(|s| s.contains(TAG)) {
            let hit = line
                .trim()
                .rsplit_once(" # handle ")
                .and_then(|(body, handle)| {
                    handle.parse::<u64>().ok()?;
                    expected.get(&(chain, body.to_owned()))
                });
            match hit {
                Some(o) if seen.insert((*o).clone()) => (),
                _ if strict => return Err(err("неизвестное или повторное правило AWG в inet fw4")),
                _ => (),
            }
        }
    }
    Ok(seen)
}

// After a firewall reload a renamed zone, or the entire fw4 table, may
// already be gone. Teardown must still remove our other rules and routes.
// A failed read alone cannot establish absence.
fn chain_absent(k: &Kernel<'_>, chain: &str) -> io::Result<bool> {
    let listing = k.call("nft", &["list", "chains", "inet"])?;
    let mut fw4 = false;
    for line in listing.lines() {
        let mut tokens = line.split_ascii_whitespace();
        match tokens.next() {
            Some("table") => fw4 = tokens.next() == Some("inet") && tokens.next() == Some("fw4"),
            Some("chain") if fw4 && tokens.next() == Some(chain) => return Ok(false),
            _ => (),
        }
    }
    Ok(true)
}

// Re-read handles under fw4's own reload lock and submit all changes as a
// single nft transaction. A reload may have recycled handles since inventory.
// Arguments contain only validated interface names and canonical IP prefixes.
pub(super) const UPDATE: &str = include_str!("fw4-update.sh");

pub(super) fn update(
    k: &Kernel<'_>,
    current: &BTreeSet<Object>,
    target: &BTreeSet<Object>,
) -> io::Result<()> {
    fn diff(from: &BTreeSet<Object>, to: &BTreeSet<Object>) -> String {
        let mut lines = String::new();
        for o in from.difference(to) {
            if let Object::Native(s, iface, kind) = o {
                writeln!(lines, "{}\t{}", kind.chain(), kind.body(*s, iface)).unwrap();
            }
        }
        lines
    }
    let remove = diff(current, target);
    let add = diff(target, current);
    if !add.is_empty() || !remove.is_empty() {
        let changed: BTreeSet<_> = current
            .symmetric_difference(target)
            .filter_map(|o| match o {
                Object::Native(_, _, kind) => Some(kind.chain()),
                _ => None,
            })
            .collect();
        let chains = changed.iter().copied().collect::<Vec<_>>().join(" ");
        let mut zones = target.iter().filter_map(|o| match o {
            Object::Native(_, _, Rule::Forward(c)) => c.strip_prefix("forward_"),
            _ => None,
        });
        let zone = if add.is_empty() {
            ""
        } else {
            let z = zones
                .next()
                .ok_or_else(|| err("fw4: не установлена зона LAN"))?;
            if zones.any(|other| other != z) {
                return Err(err("fw4: неоднозначная зона LAN"));
            }
            z
        };
        let mut known = String::new();
        if !add.is_empty() {
            for o in current {
                if let Object::Native(s, iface, kind) = o {
                    if changed.contains(kind.chain()) {
                        writeln!(known, "{}\t{}", kind.chain(), kind.body(*s, iface)).unwrap();
                    }
                }
            }
        }
        if k.call(
            "sh",
            &[
                "-c", UPDATE, "awg-fw4", &remove, &add, &chains, zone, &known,
            ],
        )? == "fw4-refused"
        {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, Refused));
        }
    }
    Ok(())
}

/// A firewall reload forgets native rules, while routing and the 90-second
/// trial still belong to the same generation. Never extend the trial or
/// change routes while handling a notification from another writer.
pub(super) fn reassert(
    db: &super::Store,
    tx: &super::Transaction<'_>,
    k: &Kernel<'_>,
    journal: &super::Journal,
    now: u64,
    authority: Option<&Authority>,
    peer: impl FnMut(&serde_json::Value, &str) -> io::Result<super::LivePeer>,
) -> io::Result<()> {
    let started = std::time::Instant::now();
    let plan = journal.installed.as_ref();
    let parked = authority
        .map(|authority| {
            let doc = nfqws2_awg_profile::read(db)?;
            authority.parked_fw4_proof(&doc, journal)
        })
        .transpose()?
        .flatten();
    if parked.is_none() && authority.is_some_and(Authority::has_named_endpoint) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    if plan.firewall != super::plan::Backend::Fw4
        || !journal.preparing.is_empty()
        || journal.expires != 0 && now >= journal.expires
        || plan.empty()
    {
        return Ok(());
    }
    if super::boot_id(k)? != journal.boot {
        return Err(err(
            "fw4: требуется восстановление маршрутов после перезагрузки",
        ));
    }
    let zone = k.lan_zone(plan.firewall)?;
    let renamed = zone != plan.fw4_zone;
    let result = restore_rules(
        db,
        tx,
        k,
        journal,
        (now, started, parked.as_ref()),
        zone,
        peer,
    );
    if renamed && result.is_err() {
        // The old chain may survive, reassigned to an unrelated network. A
        // failed revalidation must not leave our forwarding grant there.
        let retired: BTreeSet<_> = journal
            .claims()
            .into_iter()
            .filter(|o| matches!(o, Object::Native(_, _, Rule::Forward(_))))
            .collect();
        let empty = BTreeSet::new();
        let present = inventory(k, &retired, &empty, false)?;
        update(k, &present, &empty)?;
    }
    result
}

fn restore_rules(
    db: &super::Store,
    tx: &super::Transaction<'_>,
    k: &Kernel<'_>,
    journal: &super::Journal,
    (now, started, parked): (u64, std::time::Instant, Option<&Proof<'_>>),
    zone: Option<String>,
    peer: impl FnMut(&serde_json::Value, &str) -> io::Result<super::LivePeer>,
) -> io::Result<()> {
    let plan = journal.installed.as_ref();
    let renamed = zone != plan.fw4_zone;
    let mut next = journal.clone();
    if renamed {
        next.installed.fw4_zone.clone_from(&zone);
        if next.committed.firewall == super::plan::Backend::Fw4 {
            next.committed.fw4_zone.clone_from(&zone);
        }
    }
    let expected = super::objects(&next.installed);
    let previous = renamed.then(|| journal.claims());
    let claims = previous.as_ref().unwrap_or(&expected);
    let desired = expected
        .iter()
        .filter(|o| matches!(o, Object::Native(..)))
        .cloned()
        .collect::<BTreeSet<_>>();
    if desired.is_empty() && !renamed {
        return Ok(());
    }
    let current = inventory(k, claims, &desired, true)?;
    if !renamed && current == desired {
        return Ok(());
    }
    let doc = nfqws2_awg_profile::read(db)?;
    let live = if let Some(proof) = parked {
        let mut no_peer_proof = |_: &_, _: &_| Ok(None);
        plan::resolve_with_mtu_edit(
            &doc,
            next.installed.as_ref().clone(),
            true,
            Some(plan),
            Some(plan::Verification::Read(k)),
            plan::EditContext::Applying(proof, &mut no_peer_proof),
            peer,
        )?
    } else {
        let predecessor = super::mtu_edit::pending_predecessor(db, &doc, journal)?;
        let previous = predecessor.as_ref().map(|_| plan);
        plan::restore_with_predecessor(
            &doc,
            &next.installed,
            previous,
            k,
            predecessor.as_ref(),
            peer,
        )?
    };
    if super::objects(&live.plan) != expected {
        return Err(err("fw4: изменилось подтверждённое подключение AWG"));
    }
    k.guard(plan, &live.endpoints)?;
    let found = k.inventory_for(claims, &expected, true)?;
    if expected
        .difference(&found)
        .any(|o| !matches!(o, Object::Native(..)))
    {
        return Err(err("fw4: изменились маршруты подтверждённой политики AWG"));
    }
    k.verify_forward(plan)?;
    if journal.expires != 0 && now.saturating_add(started.elapsed().as_secs()) >= journal.expires {
        return Ok(());
    }
    if renamed {
        let mut pending = journal.clone();
        pending.preparing.push(next.installed.clone());
        pending.check_size()?;
        tx.save_runtime_bounded(super::RECEIPT, &pending, super::RECEIPT_LIMIT)?;
    }
    let result = update(k, &found, &expected);
    if result.as_ref().is_err_and(refused) {
        if renamed {
            tx.save_runtime_bounded(super::RECEIPT, journal, super::RECEIPT_LIMIT)?;
        }
        return result;
    }
    // An interrupted nft command may already have committed the complete
    // batch. Check actual tagged bodies rather than retrying stale handles.
    let combined = renamed.then(|| claims.union(&desired).cloned().collect());
    let after = inventory(k, combined.as_ref().unwrap_or(&desired), &desired, true)?;
    if after == desired {
        if renamed {
            tx.save_runtime_bounded(super::RECEIPT, &next, super::RECEIPT_LIMIT)?;
        }
        Ok(())
    } else {
        // nft batches are atomic. If nothing changed, keep the original
        // unexpired trial rather than leaving a partial intent for recovery.
        if renamed && after == current {
            tx.save_runtime_bounded(super::RECEIPT, journal, super::RECEIPT_LIMIT)?;
        }
        result.and(Err(err("fw4 не подтвердил восстановление правил AWG")))
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "requires unshare -n, CAP_NET_ADMIN and nftables"]
fn native_fw4_round_trip_in_isolated_netns() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let mut rows = String::new();
    for (source, dest) in [
        ("192.168.2.0/25", "203.0.113.24"),
        ("0.0.0.0/0", "198.51.100.128/25"),
        ("fd12:3456::a", "2001:db8:1111::7"),
        ("::/0", "2001:db8:2222::/64"),
    ] {
        let s = Selector {
            source: source.parse().unwrap(),
            dest: dest.parse().unwrap(),
        };
        for kind in rules(None) {
            writeln!(rows, "{}\t{}", kind.chain(), kind.body(s, "awg0")).unwrap();
        }
    }
    let script = r#"
        set -eu
        nft -f - <<'EOF'
table inet fw4 {
    chain srcnat { type nat hook postrouting priority srcnat; policy accept; }
    chain forward_lan { }
    chain forward { type filter hook forward priority filter; policy drop; jump forward_lan; }
    chain mangle_forward { type filter hook forward priority mangle; policy accept; }
}
EOF
        nft 'add rule inet fw4 forward_lan oifname "eth1" drop comment "admin"'
        chains="srcnat forward_lan mangle_forward"
        sh -c "$1" awg-fw4 "" "$2" "$chains" lan ""
        test "$(nft list table inet fw4 | grep -c 'n2s-awg-cidr')" = 12
        test "$(sh -c "$1" awg-fw4 "" "$2" "$chains" lan "")" = fw4-refused
        sh -c "$1" awg-fw4 "$2" "" "$chains" "" ""
        nft list table inet fw4
    "#;
    let output = Command::new("unshare")
        .args(["-n", "sh", "-c", script, "test-fw4"])
        .arg(
            UPDATE
                .replace("/var/run/fw4.lock", "\"$TEST_FW4_LOCK\"")
                .replace("utpl -S /usr/share/firewall4/main.uc", "echo lan"),
        )
        .arg(rows)
        .env("TEST_FW4_LOCK", temp.path().join("fw4.lock"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8(output.stdout).unwrap();
    assert!(listing.contains("admin") && !listing.contains(TAG));
}
