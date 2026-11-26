//! A large unscoped Keenetic policy uses one destination FIB and one firewall
//! set per tunnel and address family. The existing journal still claims every
//! prefix and verifies the exact membership before deleting or adopting it.
use super::{
    err,
    inventory::{Kernel, Object},
    plan::{Family, Plan, Prefix},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    io,
};

pub(super) const OLD_LIMIT: usize = 16_384;
pub(super) const ZONE_LIMIT: usize = 65_536;
pub(super) const LIMIT: usize = 4 * ZONE_LIMIT;
pub(super) fn name(family: Family, iface: &str) -> String {
    format!(
        "n2srt{}_{}",
        if family == Family::V4 { 4 } else { 6 },
        iface
    )
}
pub(super) fn in_use(objects: &BTreeSet<Object>) -> bool {
    objects.iter().any(|o| {
        matches!(
            o,
            Object::Set(..) | Object::SetMember(..) | Object::SetFirewall(..)
        )
    })
}
pub(super) fn batched(object: &Object) -> bool {
    matches!(
        object,
        Object::Set(..) | Object::SetMember(..) | Object::Route(..)
    )
}

pub(super) fn check_header(line: &str, set: &str, family: Family) -> bool {
    let w: Vec<_> = line.split_ascii_whitespace().collect();
    let Some(opts) = w.strip_prefix(&["create", set, "hash:net"]) else {
        return false;
    };
    let valid = opts.chunks_exact(2).all(|p| match p {
        ["family", f] => *f == family.inet(),
        ["maxelem", "65536"] => true,
        ["hashsize" | "bucketsize", n] => n.parse::<u32>().is_ok_and(|n| n > 0),
        ["initval", n] => n
            .strip_prefix("0x")
            .is_some_and(|s| u32::from_str_radix(s, 16).is_ok()),
        _ => false,
    });
    valid
        && opts.len().is_multiple_of(2)
        && opts.chunks_exact(2).any(|p| p == ["family", family.inet()])
        && opts.chunks_exact(2).any(|p| p == ["maxelem", "65536"])
}

pub(super) fn inventory(
    k: &Kernel<'_>,
    claims: &BTreeSet<Object>,
    proposed: &BTreeSet<Object>,
) -> io::Result<BTreeSet<Object>> {
    let groups: BTreeSet<_> = claims
        .iter()
        .chain(proposed)
        .filter_map(|o| match o {
            Object::Set(f, i) => Some((*f, i.as_str())),
            _ => None,
        })
        .collect();
    let mut found = BTreeSet::new();
    if groups.is_empty() {
        return Ok(found);
    }
    let names = k.call("ipset", &["list", "-name"])?;
    for (family, iface) in groups {
        let set = name(family, iface);
        if !names.lines().any(|n| n == set) {
            continue;
        }
        let object = Object::Set(family, iface.to_owned());
        if !claims.contains(&object) {
            return Err(err("имя IP-набора занято другим владельцем"));
        }
        let saved = k.call("ipset", &["save", &set])?;
        let mut lines = saved.lines();
        if !lines.next().is_some_and(|l| check_header(l, &set, family)) {
            return Err(err("параметры управляемого IP-набора изменены"));
        }
        found.insert(object);
        let membership: std::sync::Arc<str> = iface.into();
        for line in lines {
            let mut w = line.split_ascii_whitespace();
            if w.next() != Some("add") || w.next() != Some(set.as_str()) {
                return Err(err("неожиданная запись IP-набора"));
            }
            let p: Prefix = w
                .next()
                .ok_or_else(|| err("нет адреса в IP-наборе"))?
                .parse()?;
            let object = Object::SetMember(p, membership.clone());
            if w.next().is_some()
                || p.family() != family
                || !claims.contains(&object)
                || !found.insert(object)
            {
                return Err(err("IP-набор содержит запись другого владельца"));
            }
        }
    }
    Ok(found)
}

pub(super) fn check_references(k: &Kernel<'_>, seen: &BTreeSet<Object>) -> io::Result<()> {
    let mut refs_by_set = BTreeMap::<(Family, &str), usize>::new();
    for o in seen {
        match o {
            Object::LegacyClassifier(family, rules) => {
                for rule in rules {
                    *refs_by_set.entry((*family, &rule.token)).or_default() += 1;
                }
            }
            Object::GroupFirewall(f, _, dest, source, _) => {
                if let Some(src) = source {
                    *refs_by_set.entry((*f, src)).or_default() += 1;
                }
                *refs_by_set.entry((*f, dest)).or_default() += 1;
            }
            Object::SetFirewall(f, key, _) => *refs_by_set.entry((*f, key)).or_default() += 1,
            Object::Classifier(f, groups) => {
                for group in groups {
                    *refs_by_set.entry((*f, &group.token)).or_default() += 4;
                    if let Some(src) = &group.source {
                        *refs_by_set.entry((*f, src)).or_default() += 4;
                    }
                }
            }
            _ => (),
        }
    }
    for o in seen {
        let Object::Set(f, i) = o else { continue };
        let set = name(*f, i);
        let header = k.call("ipset", &["list", &set, "-terse"])?;
        let refs = header
            .lines()
            .find_map(|l| l.strip_prefix("References:"))
            .and_then(|n| n.trim().parse::<usize>().ok());
        let expected = refs_by_set
            .get(&(*f, i.as_str()))
            .copied()
            .unwrap_or_default();
        if refs != Some(expected) {
            return Err(err("IP-набор используется посторонним правилом firewall"));
        }
    }
    Ok(())
}

fn apply(k: &Kernel<'_>, name: &str, args: &[&str], document: &str) -> io::Result<()> {
    if !document.is_empty() {
        k.run
            .run_input(name, args, document.as_bytes(), k.deadline)?;
    }
    Ok(())
}
pub(super) fn create(
    k: &Kernel<'_>,
    from: &BTreeSet<Object>,
    to: &BTreeSet<Object>,
) -> io::Result<()> {
    let mut doc = String::new();
    // Set precedes SetMember in Object's ordering.
    for o in to.difference(from) {
        match o {
            Object::Set(f, i) => writeln!(
                doc,
                "create {} hash:net family {} hashsize 1024 maxelem 65536",
                name(*f, i),
                f.inet()
            )
            .unwrap(),
            Object::SetMember(p, i) => writeln!(doc, "add {} {p}", name(p.family(), i)).unwrap(),
            _ => (),
        }
    }
    apply(k, "ipset", &["restore"], &doc)
}
pub(super) fn finish(
    k: &Kernel<'_>,
    from: &BTreeSet<Object>,
    to: &BTreeSet<Object>,
) -> io::Result<()> {
    routes(k, from, to, true, true)?;
    remove_sets(k, from, to)
}
pub(super) fn routes(
    k: &Kernel<'_>,
    from: &BTreeSet<Object>,
    to: &BTreeSet<Object>,
    add: bool,
    remove: bool,
) -> io::Result<()> {
    let ip =
        k.ip.get()
            .ok_or_else(|| err("не определён iproute2 для таблиц AWG"))?
            .0;
    for family in [Family::V4, Family::V6] {
        let routes = |set: &BTreeSet<Object>| -> BTreeMap<(Prefix, u16), String> {
            set.iter()
                .filter_map(|o| match o {
                    Object::Route(p, i, t) if p.family() == family => Some(((*p, *t), i.clone())),
                    _ => None,
                })
                .collect()
        };
        let live = routes(from);
        let target = routes(to);
        let mut doc = String::new();
        for (&(p, t), i) in &target {
            if !add {
                break;
            }
            let change = match live.get(&(p, t)) {
                None => "add",
                Some(old) if old != i => "replace",
                _ => continue,
            };
            writeln!(doc, "route {change} table {t} {p} dev {i} proto 242").unwrap();
        }
        for (&(p, t), i) in &live {
            if !remove {
                break;
            }
            if !target.contains_key(&(p, t)) {
                writeln!(doc, "route del table {t} {p} dev {i} proto 242").unwrap();
            }
        }
        apply(k, ip, &[family.flag(), "-batch", "-"], &doc)?;
    }
    Ok(())
}
pub(super) fn remove_sets(
    k: &Kernel<'_>,
    from: &BTreeSet<Object>,
    to: &BTreeSet<Object>,
) -> io::Result<()> {
    let mut doc = String::new();
    for o in from.iter().rev().filter(|o| !to.contains(o)) {
        match o {
            Object::SetMember(p, i) => writeln!(doc, "del {} {p}", name(p.family(), i)).unwrap(),
            Object::Set(f, i) => writeln!(doc, "destroy {}", name(*f, i)).unwrap(),
            _ => (),
        }
    }
    apply(k, "ipset", &["restore"], &doc)
}

pub(super) fn verify(
    k: &Kernel<'_>,
    plan: &Plan,
    previous: Option<&BTreeSet<Object>>,
) -> io::Result<()> {
    let ip =
        k.ip.get()
            .ok_or_else(|| err("не определён iproute2 для проверки AWG"))?
            .0;
    for family in [Family::V4, Family::V6] {
        let mut expected = Vec::new();
        for (s, i) in plan.flows().filter(|(s, _)| s.dest.family() == family) {
            let Some(iface) = plan.effective(s, i) else {
                continue;
            };
            if previous.is_some_and(|objects| {
                objects.contains(&Object::PackedLookup(family))
                    && objects.contains(&Object::Route(s.dest, iface.into(), 17842))
            }) {
                continue;
            }
            let addr = s.dest.sample();
            expected.push((addr, iface));
        }
        if expected.is_empty() {
            continue;
        }
        for group in expected.chunks(2048) {
            let mut document = String::new();
            for (addr, _) in group {
                writeln!(document, "route get {addr}").unwrap();
            }
            let output = k.run.run_input(
                ip,
                &["-o", family.flag(), "-batch", "-"],
                document.as_bytes(),
                k.deadline,
            )?;
            let mut lines = output.lines();
            for &(addr, iface) in group {
                let mut words = lines.next().unwrap_or_default().split_ascii_whitespace();
                if words.next().and_then(|w| w.parse().ok()) != Some(addr)
                    || words.skip_while(|&w| w != "dev").nth(1) != Some(iface)
                {
                    return Err(err("ядро выбрало другой интерфейс для адреса зоны"));
                }
            }
            if lines.next().is_some() {
                return Err(err("лишний результат проверки маршрутов"));
            }
        }
    }
    Ok(())
}
