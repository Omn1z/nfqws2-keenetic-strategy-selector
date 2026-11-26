use super::{err, io, BTreeMap, BTreeSet, Family, Kernel, Object, MASK};
use crate::kernel::inventory::{PREF, PROTO};

pub(super) fn metric(family: Family) -> &'static str {
    match family {
        Family::V4 => "1000",
        // The device route has Linux's default IPv6 metric 1024.
        Family::V6 => "32760",
    }
}

pub(in crate::kernel) fn mutate(
    k: &Kernel<'_>,
    family: Family,
    slot: u8,
    add: bool,
) -> io::Result<()> {
    k.call(
        "ip",
        &[
            family.flag(),
            "route",
            if add { "add" } else { "del" },
            "blackhole",
            "default",
            "table",
            &super::table(slot).to_string(),
            "proto",
            PROTO,
            "metric",
            metric(family),
        ],
    )?;
    Ok(())
}

fn conflict() -> io::Error {
    err("маршрут или правило таблицы Kill Switch AWG не соответствует журналу")
}

pub(in crate::kernel) fn parse(f: Family, table: u16, words: &[&str]) -> io::Result<Object> {
    let [kind, dest, attrs @ ..] = words else {
        return Err(conflict());
    };
    if !matches!(*kind, "blackhole" | "6")
        || *dest != "default"
        || !(18000..=18128).contains(&table)
    {
        return Err(conflict());
    }
    let mut seen = BTreeSet::new();
    let mut pairs = attrs.chunks_exact(2);
    if !pairs.all(|pair| {
        seen.insert(pair[0])
            && match pair {
                ["table", id] => id.parse::<u16>() == Ok(table),
                ["proto", PROTO] => true,
                ["metric", m] => *m == metric(f),
                ["scope", "global" | "0"] => true,
                ["dev", "lo"] | ["pref", "medium" | "0"] | ["error", "-22"] => f == Family::V6,
                _ => false,
            }
    }) || !pairs.remainder().is_empty()
        || !["table", "proto", "metric"]
            .iter()
            .all(|k| seen.contains(k))
    {
        return Err(conflict());
    }
    Ok(Object::MarkFence(f, (table - 18000) as u8))
}

fn field<'a>(words: &'a [&str], key: &str) -> Option<&'a str> {
    words.windows(2).find(|v| v[0] == key).map(|v| v[1])
}
fn number(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

// Earlier source-, interface- and destination-based rules are not exercised
// by a single route-get probe from the router's own address. A validated
// blackhole in the later table cannot protect packets claimed before it.
pub(super) fn check_priorities(
    text: &str,
    slots: &BTreeSet<u8>,
    f: Family,
    target: &BTreeSet<Object>,
) -> io::Result<()> {
    if slots.is_empty() {
        return Ok(());
    }
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let w: Vec<_> = line.split_ascii_whitespace().collect();
        let pref = w[0]
            .strip_suffix(':')
            .and_then(|n| n.parse::<u32>().ok())
            .ok_or_else(conflict)?;
        if pref >= 68
            || matches!(
                w.as_slice(),
                ["0:", "from", "all", "lookup", "255" | "local"]
            )
        {
            continue;
        }
        if !w.contains(&"not") {
            if let Some(raw) = field(&w, "fwmark") {
                let (value, mask) = raw.split_once('/').unwrap_or((raw, "0xffffffff"));
                let (value, mask) = (
                    number(value).ok_or_else(conflict)?,
                    number(mask).ok_or_else(conflict)?,
                );
                // The classifier observes a clear AWG transport bypass bit,
                // and writes exactly MASK. Other ordinary mark bits survive.
                if slots.iter().all(|s| {
                    (value ^ (0x10000000 | (u32::from(*s) << 20))) & mask & (MASK | 0x20000000) != 0
                }) || mask & 0x8000ff80 == 0x8000ff80 && value & 0x8000ff80 == 0x8000d500
                {
                    continue;
                }
            }
            if disjoint_scope(&w, f, target, slots) {
                continue;
            }
        }
        return Err(err(
            "более раннее правило маршрутизации может обойти Kill Switch AWG",
        ));
    }
    Ok(())
}

fn disjoint_scope(
    words: &[&str],
    family: Family,
    target: &BTreeSet<Object>,
    slots: &BTreeSet<u8>,
) -> bool {
    use super::Prefix;
    let bound = |key| {
        field(words, key)
            .and_then(|n| n.parse::<Prefix>().ok())
            .filter(|p| p.family() == family && !p.any())
    };
    let (source, dest) = (bound("from"), bound("to"));
    if source.is_none() && dest.is_none() {
        return false;
    }
    let mut possible_src = BTreeSet::new();
    let mut possible_dst = BTreeSet::new();
    for obj in target {
        if let Object::SetMember(prefix, name) = obj {
            if source.is_some_and(|s| prefix.overlaps(s)) {
                possible_src.insert(name.as_ref());
            }
            if dest.is_some_and(|d| prefix.overlaps(d)) {
                possible_dst.insert(name.as_ref());
            }
        }
    }
    let mut matched_slot = false;
    for obj in target {
        let Object::Classifier(f, groups) = obj else {
            continue;
        };
        if *f != family {
            continue;
        }
        for g in groups.iter().filter(|g| slots.contains(&g.slot)) {
            matched_slot = true;
            if (source.is_none()
                || g.source
                    .as_ref()
                    .is_none_or(|token| possible_src.contains(token.as_str())))
                && (dest.is_none() || possible_dst.contains(g.token.as_str()))
            {
                return false;
            }
        }
    }
    matched_slot
}

pub(in crate::kernel) fn verify(k: &Kernel<'_>, target: &BTreeSet<Object>) -> io::Result<()> {
    for f in [Family::V4, Family::V6] {
        let slots = target
            .iter()
            .filter_map(|o| match o {
                Object::MarkFence(family, slot) if f == *family => Some(*slot),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if slots.is_empty() {
            continue;
        }
        let tables = slots
            .iter()
            .map(|s| (super::table(*s), *s))
            .collect::<BTreeMap<_, _>>();
        let mut fences = BTreeSet::new();
        let mut seen_routes = BTreeSet::new();
        let expected_routes = target
            .iter()
            .filter_map(|o| match o {
                Object::Route(prefix, _, table)
                    if *prefix == f.any() && tables.contains_key(table) =>
                {
                    Some(*table)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for row in k.listing(f, &["route", "show", "table", "all"])?.lines() {
            let w = row.split_ascii_whitespace().collect::<Vec<_>>();
            let Some(table) = field(&w, "table")
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|t| tables.contains_key(t))
            else {
                continue;
            };
            if matches!(w.first(), Some(&"blackhole" | &"6")) {
                parse(f, table, &w)?;
                if !fences.insert(table) {
                    return Err(conflict());
                }
            } else {
                let dev = field(&w, "dev").ok_or_else(conflict)?;
                if !matches!(w.first(), Some(&"default"))
                    && w.first().and_then(|v| v.parse().ok()) != Some(f.any())
                    || field(&w, "proto") != Some(PROTO)
                    || !target.contains(&Object::Route(f.any(), dev.into(), table))
                    || !seen_routes.insert(table)
                {
                    return Err(conflict());
                }
                let mut pairs = w[1..].chunks_exact(2);
                let mut attrs = BTreeSet::new();
                if !pairs.all(|p| {
                    attrs.insert(p[0])
                        && (matches!(
                            p,
                            ["dev", _] | ["proto", _] | ["table", _] | ["scope", "link" | "253"]
                        ) || f == Family::V6
                            && matches!(p, ["metric", "1024"] | ["pref", "medium" | "0"]))
                }) || !pairs.remainder().is_empty()
                {
                    return Err(conflict());
                }
            }
        }
        let listing = k.listing(f, &["rule", "show"])?;
        check_priorities(&listing, &slots, f, target)?;
        let mut lookups = BTreeSet::new();
        for row in listing.lines() {
            let w = row.split_ascii_whitespace().collect::<Vec<_>>();
            let Some(table) = field(&w, "lookup")
                .and_then(|t| t.parse::<u16>().ok())
                .filter(|t| tables.contains_key(t))
            else {
                continue;
            };
            let [pref, "from", "all", "fwmark", mark, "lookup", id] = w.as_slice() else {
                return Err(conflict());
            };
            if pref.strip_suffix(':') != Some(PREF)
                || super::slot(mark, id) != Some(tables[&table])
                || !lookups.insert(table)
            {
                return Err(conflict());
            }
        }
        if seen_routes != expected_routes
            || tables
                .keys()
                .any(|t| !fences.contains(t) || !lookups.contains(t))
        {
            return Err(err(
                "ядро не подтвердило защитный маршрут и правило Kill Switch AWG",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_family_protocol_metric_and_kernel_attributes_prove_fence_ownership() {
        let read =
            |f, text: &str| parse(f, 18002, &text.split_ascii_whitespace().collect::<Vec<_>>());
        assert_eq!(
            read(
                Family::V4,
                "blackhole default table 18002 proto 242 metric 1000"
            )
            .unwrap(),
            Object::MarkFence(Family::V4, 2)
        );
        assert_eq!(
            read(
                Family::V6,
                "6 default dev lo table 18002 proto 242 metric 32760 error -22 pref 0"
            )
            .unwrap(),
            Object::MarkFence(Family::V6, 2)
        );
        for row in [
            "blackhole default table 18002 proto 4 metric 32760",
            "blackhole default table 18002 proto 242 metric 1024",
            "blackhole default table 18003 proto 242 metric 32760",
            "blackhole default table 18002 proto 242 metric 32760 dev tun0",
            "blackhole default table 18002 proto 242 proto 242 metric 32760",
            "blackhole default table 18002 proto 242 metric 32760 pref high",
            "unreachable default table 18002 proto 242 metric 32760",
            "blackhole ::/1 table 18002 proto 242 metric 32760",
        ] {
            assert!(read(Family::V6, row).is_err(), "{row}");
        }
    }
    #[test]
    fn earlier_source_or_inverted_fwmark_rules_cannot_bypass_the_guarded_lookup() {
        let slots = BTreeSet::from([0, 2]);
        let check = |row| check_priorities(row, &slots, Family::V4, &BTreeSet::new());
        for row in [
            "0: from all lookup local",
            "0: from all lookup 255",
            "42: from all fwmark 0xa0000001 lookup 100",
            "75: from all lookup main",
        ] {
            check(row).unwrap();
        }
        for row in [
            "42: from all lookup main",
            "42: from 192.168.1.1 lookup 77",
            "42: not from all fwmark 0xa0000001 lookup 100",
            "42: from all fwmark 0x10000000/0x10000000 lookup 100",
            "62: from all fwmark 0x10200000/0x1ff00000 lookup 902",
        ] {
            assert!(check(row).is_err(), "{row}");
        }
    }
}
