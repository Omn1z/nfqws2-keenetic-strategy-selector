//! Large policies. The compiler resolves first-match winners into disjoint
//! source and destination ranges. A classified packet shares one default
//! route with the other destinations handled by the same authenticated peer.
use super::{
    err,
    inventory::{Firewall, Kernel, Object},
    packed,
    plan::{Family, Plan, Prefix},
};
use sha2::{Digest, Sha256};
pub(super) mod fence;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    io,
};

const MASK: u32 = 0x1ff00000;
pub(super) const TAG: &str = "n2s-awg-setroute";
const CHUNK: usize = 4096;
const LISTING_BYTES: usize = 4 << 20; // A complete xtables listing must fit Runner::run.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Group {
    pub token: String,
    pub source: Option<String>,
    pub slot: u8,
}
pub(super) fn table(slot: u8) -> u16 {
    18000 + u16::from(slot)
}
pub(super) fn mark(slot: u8) -> String {
    format!("{:#x}", 0x10000000 | (u32::from(slot) << 20))
}
pub(super) fn masked(slot: u8) -> String {
    format!("{}/{MASK:#x}", mark(slot))
}
pub(super) fn slot(masked_mark: &str, table_id: &str) -> Option<u8> {
    let s: u8 = table_id
        .parse::<u16>()
        .ok()?
        .checked_sub(18000)?
        .try_into()
        .ok()?;
    (s <= 128 && masked(s) == masked_mark).then_some(s)
}
pub(super) fn token(prefixes: &[Prefix]) -> String {
    let mut digest = Sha256::new();
    for net in prefixes {
        digest.update(net.to_string().as_bytes());
        digest.update([0]);
    }
    let mut token = String::from("g");
    for b in &digest.finalize()[..11] {
        write!(token, "{b:02x}").unwrap();
    }
    token
}
fn add_set(family: Family, nets: &[Prefix], out: &mut BTreeSet<Object>) -> String {
    let key = token(nets);
    if out.insert(Object::Set(family, key.clone())) {
        let membership: std::sync::Arc<str> = key.as_str().into();
        out.extend(
            nets.iter()
                .map(|p| Object::SetMember(*p, membership.clone())),
        );
    }
    key
}
// Bound the largest table before allocating source-chunk × destination-chunk
// rules. Each group adds four classifiers and at most one MSS rule to mangle.
pub(super) fn check_size(plan: &Plan) -> io::Result<()> {
    let mut buckets = BTreeMap::<(Prefix, Option<&str>, u8), usize>::new();
    for (s, primary) in plan.flows() {
        let iface = plan.effective(s, primary);
        if iface.is_some() || plan.protected(primary) {
            *buckets
                .entry((s.source, iface, s.dest.bucket()))
                .or_default() += 1;
        }
    }
    let cost = |scoped: bool| {
        let token = "g0000000000000000000000".to_owned();
        let group = Group {
            token: token.clone(),
            source: scoped.then(|| token.clone()),
            slot: 128,
        };
        let rules = ["OUTPUT", "PREROUTING"]
            .into_iter()
            .flat_map(|p| rules(Family::V4, std::slice::from_ref(&group), p));
        // -A, quoted comment and newline in iptables -S.
        let bytes = rules.map(|r| r.len() + 6).sum::<usize>();
        let clamp = Object::GroupFirewall(
            Family::V4,
            "awg000000000000".into(),
            token,
            group.source,
            Firewall::Clamp,
        );
        let (_, chain, spec) = clamp.xtables().expect("group firewall");
        bytes + chain.len() + spec.join(" ").len() + 7
    };
    let own_bytes = [cost(false), cost(true)];
    let mut totals = BTreeMap::<Family, usize>::new();
    for ((src, _, _), items) in buckets {
        let sources = plan
            .source_ranges
            .get(&src)
            .map_or(1, |v| v.len().div_ceil(CHUNK));
        let bytes = totals.entry(src.family()).or_default();
        *bytes += own_bytes[usize::from(!src.any())] * sources * items.div_ceil(CHUNK);
        if *bytes > LISTING_BYTES {
            return Err(err(
                "правила классификатора не помещаются в проверяемый снимок таблицы mangle",
            ));
        }
    }
    Ok(())
}
pub(super) fn objects(plan: &Plan, out: &mut BTreeSet<Object>) {
    let mut groups = BTreeMap::<(Prefix, Option<&str>, u8), Vec<Prefix>>::new();
    for (s, primary) in plan.flows() {
        let iface = plan.effective(s, primary);
        if let Some(i) = iface {
            if plan.protected(primary) || plan.protected(i) {
                out.insert(Object::MarkFence(s.dest.family(), plan.marks[i]));
            }
        }
        if iface.is_some() || plan.protected(primary) {
            groups
                .entry((s.source, iface, s.dest.bucket()))
                .or_default()
                .push(s.dest);
        }
    }
    let mut sources = BTreeMap::<Prefix, Vec<Option<String>>>::new();
    let mut policies = BTreeMap::<Family, BTreeSet<Group>>::new();
    for ((src, iface, _), dests) in groups {
        let f = src.family();
        let slot = iface.map_or(0, |i| plan.marks[i]);
        out.insert(Object::MarkLookup(f, slot));
        if let Some(i) = iface {
            out.insert(Object::Route(f.any(), i.into(), table(slot)));
        } else {
            out.insert(Object::MarkFence(f, 0));
        }
        let src_tokens = sources.entry(src).or_insert_with(|| {
            if src.any() {
                vec![None]
            } else {
                plan.source_ranges[&src]
                    .chunks(CHUNK)
                    .map(|chunk| Some(add_set(f, chunk, out)))
                    .collect()
            }
        });
        for chunk in dests.chunks(CHUNK) {
            let dest = add_set(f, chunk, out);
            for source in src_tokens.iter() {
                if let Some(i) = iface {
                    for &fw in Firewall::legacy_rules(plan) {
                        out.insert(Object::GroupFirewall(
                            f,
                            i.into(),
                            dest.clone(),
                            source.clone(),
                            fw,
                        ));
                    }
                }
                policies.entry(f).or_default().insert(Group {
                    token: dest.clone(),
                    source: source.clone(),
                    slot,
                });
            }
        }
    }
    for (f, groups) in policies {
        out.insert(Object::Classifier(f, groups.into_iter().collect()));
    }
}
pub(super) fn owned(o: &Object) -> bool {
    match o {
        Object::Set(_, key) => key.starts_with('g'),
        Object::SetMember(_, key) => key.starts_with('g'),
        Object::Route(_, _, t) => (18001..=18128).contains(t),
        Object::MarkLookup(..)
        | Object::MarkFence(..)
        | Object::Classifier(..)
        | Object::GroupFirewall(..) => true,
        _ => false,
    }
}
fn generation(objects: &BTreeSet<Object>, family: Family) -> Option<&Vec<Group>> {
    objects.iter().find_map(|o| match o {
        Object::Classifier(f, g) if *f == family => Some(g),
        _ => None,
    })
}
fn rules(f: Family, groups: &[Group], parent: &str) -> Vec<String> {
    let mut out = Vec::new();
    for g in groups {
        let set = packed::name(f, &g.token);
        // DNS route sockets own 128 slots in 0x8000d500/0x8000ff80. Replies
        // carry the DNS identity in connmark before N2S_DNS_PRE queues them.
        let dns = if parent == "PREROUTING" {
            "-m connmark ! --mark 0x8000d500/0x8000ff80"
        } else {
            "-m mark ! --mark 0x8000d500/0x8000ff80"
        };
        let source = g.source.as_ref().map_or(String::new(), |token| {
            format!("-m set --match-set {} src ", packed::name(f, token))
        });
        let spec=format!("{parent} -m mark --mark 0x0/0x20000000 {dns} {source}-m set --match-set {set} dst -m comment --comment {TAG} -j");
        out.push(format!("{spec} MARK --set-xmark {}", masked(g.slot)));
        out.push(format!("{spec} ACCEPT"));
    }
    out
}
fn check_transition_size(text: &str, f: Family, target: &BTreeSet<Object>) -> io::Result<()> {
    let own = text
        .lines()
        .filter(|l| l.contains(TAG))
        .map(|l| l.len() + 1)
        .sum::<usize>();
    let desired = generation(target, f).map_or(0, |groups| {
        ["OUTPUT", "PREROUTING"]
            .into_iter()
            .flat_map(|p| rules(f, groups, p))
            .map(|r| r.len() + 6)
            .sum()
    });
    let installed = text
        .lines()
        .filter(|l| l.contains("n2srt") || l.contains("n2s-awg-cidr"))
        .map(|l| l.replace('"', ""))
        .collect::<BTreeSet<_>>();
    let mut required = text.len() + desired.saturating_sub(own);
    for obj in target {
        if obj.family() == f && (obj.fixed_mss() || matches!(obj,Object::GroupFirewall(_,_,_,_,Firewall::Clamp))) {
            let (_, chain, spec) = obj.xtables().unwrap();
            let line = format!("-A {chain} {}", spec.join(" "));
            if !installed.contains(&line) {
                required += line.len() + 3;
            }
        }
    }
    if required > LISTING_BYTES {
        return Err(err(
            "после переключения не удастся полностью сверить таблицу mangle",
        ));
    }
    Ok(())
}
fn installed(text: &str, parent: &str) -> io::Result<Vec<String>> {
    let prefix = format!("-A {parent} ");
    let mut own = Vec::new();
    let mut other = false;
    for line in text.lines().filter(|l| l.starts_with(&prefix)) {
        if !line
            .split_ascii_whitespace()
            .any(|w| w.trim_matches('"') == TAG)
        {
            if line != "-A PREROUTING -m connmark --mark 0x8000d500/0x8000ffff -j N2S_DNS_PRE"
                || !super::handoff::dns_pre_terminal(
                    &text
                        .lines()
                        .map(|l| l.split_ascii_whitespace().collect())
                        .collect::<Vec<_>>(),
                )
            {
                other = true;
            }
            continue;
        }
        if other {
            return Err(err(
                "классификатор AWG уступил приоритет постороннему правилу",
            ));
        }
        own.push(
            line[3..]
                .replace(&format!("\"{TAG}\""), TAG)
                .replace("--mark 0/0x20000000", "--mark 0x0/0x20000000"),
        );
    }
    Ok(own)
}
pub(super) fn check_rpdb(text: &str, slots: &BTreeSet<u8>, go: bool) -> io::Result<()> {
    let number = |value: &str| {
        if let Some(hex) = value.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()
        } else {
            value.parse::<u32>().ok()
        }
    };
    for line in text.lines() {
        let w = line.split_ascii_whitespace().collect::<Vec<_>>();
        let Some(mark) = w.windows(2).find(|v| v[0] == "fwmark").map(|v| v[1]) else {
            continue;
        };
        let (value, mask) = mark.split_once('/').unwrap_or((mark, "0xffffffff"));
        let (Some(value), Some(mask)) = (number(value), number(mask)) else {
            return Err(err("не удалось сверить метку правила маршрутизации"));
        };
        if mask & MASK == 0
            || !slots
                .iter()
                .any(|&s| (value ^ (0x10000000 | (u32::from(s) << 20))) & mask & MASK == 0)
        {
            continue;
        }
        let table = w
            .windows(2)
            .find(|v| v[0] == "lookup")
            .map(|v| v[1])
            .unwrap_or_default();
        if matches!(
            w.as_slice(),
            ["68:", "from", "all", "fwmark", _, "lookup", _]
        ) && slot(mark, table).is_some()
        {
            continue;
        }
        if go && mask == MASK {
            if let [pref, "from", "all", "fwmark", _, "lookup", id] = w.as_slice() {
                if let Some(slot) = id.parse::<u32>().ok().and_then(|t| t.checked_sub(900)) {
                    if (1..=64).contains(&slot)
                        && value == (0x1000_0000 | slot << 20)
                        && pref.strip_suffix(':').and_then(|p| p.parse::<u32>().ok())
                            == Some(70 + slot)
                    {
                        continue;
                    }
                }
            }
        }
        // DNS sockets and nested/diagnostic transports are explicitly skipped
        // before assigning the new mark. Their rules cannot shadow a zone.
        if mask & 0x20000000 != 0 && value & 0x20000000 != 0
            || mask & 0x8000ff80 == 0x8000ff80 && value & 0x8000ff80 == 0x8000d500
        {
            continue;
        }
        return Err(err(
            "диапазон меток туннелей занят другой таблицей маршрутизации",
        ));
    }
    Ok(())
}
pub(super) fn inventory(
    k: &Kernel<'_>,
    claims: &BTreeSet<Object>,
    proposed: &BTreeSet<Object>,
    go: bool,
    strict: bool,
) -> io::Result<BTreeSet<Object>> {
    let mut found = BTreeSet::new();
    for f in [Family::V4, Family::V6] {
        let families = |o: &Object| matches!(o,Object::Classifier(family,_) if *family==f);
        if !claims.iter().chain(proposed).any(families) {
            continue;
        }
        let slots = claims
            .iter()
            .chain(proposed)
            .filter_map(|o| match o {
                Object::MarkLookup(family, s) if *family == f => Some(*s),
                _ => None,
            })
            .collect();
        let rpdb = k.listing(f, &["rule", "show"])?;
        check_rpdb(&rpdb, &slots, go)?;
        if strict {
            let protected = proposed
                .iter()
                .filter_map(|o| match o {
                    Object::MarkFence(family, s) if *family == f => Some(*s),
                    _ => None,
                })
                .collect();
            fence::check_priorities(&rpdb, &protected, f, proposed)?;
        }
        let mut source = k.call(f.firewall(), &["-w", "-t", "mangle", "-S"])?;
        if claims.iter().any(|o| matches!(o, Object::LegacyClassifier(family, _) if *family == f)) {
            // The full-tunnel classifier has a disjoint pair of marks. Its complete
            // rule sequence was checked by legacy_scope::inventory.
            source = source
                .lines()
                .filter(|row| {
                    !row.split_ascii_whitespace()
                        .any(|w| w.trim_matches('"') == super::legacy_scope::tag(f))
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
        if strict {
            check_transition_size(&source, f, proposed)?;
        }
        // A distinct writer of our mark range could send unrelated traffic to
        // a reserved table. Go owns the old AWG2 marks only during preflight.
        for line in source.lines() {
            let w = line.split_ascii_whitespace().collect::<Vec<_>>();
            if w.iter().any(|s| s.trim_matches('"') == TAG) {
                if !matches!(w.get(1), Some(&"OUTPUT" | &"PREROUTING")) {
                    return Err(err("обнаружен посторонний пользователь классификатора AWG"));
                }
                continue;
            }
            if go && w.get(1).is_some_and(|n| n.starts_with("AWG2_")) {
                continue;
            }
            if w.windows(2).any(|s| {
                matches!(
                    s[0],
                    "--set-mark" | "--set-xmark" | "--or-mark" | "--xor-mark"
                ) && s[1]
                    .split('/')
                    .next()
                    .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                    .is_some_and(|v| v & 0x10000000 != 0)
            }) {
                return Err(err("диапазон меток AWG занят другим правилом"));
            }
        }
        let output = installed(&source, "OUTPUT")?;
        let pre = installed(&source, "PREROUTING")?;
        if output.is_empty() && pre.is_empty() {
            continue;
        }
        let live = claims
            .iter()
            .find(|o| match o {
                Object::Classifier(family, groups) if *family == f => {
                    rules(f, groups, "OUTPUT") == output && rules(f, groups, "PREROUTING") == pre
                }
                _ => false,
            })
            .ok_or_else(|| err("действующий классификатор AWG не соответствует журналу"))?;
        found.insert(live.clone());
    }
    Ok(found)
}
fn switch(k: &Kernel<'_>, f: Family, from: &[Group], to: &[Group]) -> io::Result<()> {
    if from == to {
        return Ok(());
    }
    let mut doc = String::from("*mangle\n");
    for parent in ["OUTPUT", "PREROUTING"] {
        for rule in rules(f, from, parent) {
            writeln!(doc, "-D {rule}").unwrap();
        }
        for rule in rules(f, to, parent).iter().rev() {
            let (_, spec) = rule.split_once(' ').unwrap();
            writeln!(doc, "-I {parent} 1 {spec}").unwrap();
        }
    }
    doc.push_str("COMMIT\n");
    let tool = if f == Family::V4 {
        "iptables-restore"
    } else {
        "ip6tables-restore"
    };
    k.run
        .run_input(tool, &["--noflush"], doc.as_bytes(), k.deadline)?;
    Ok(())
}
fn auxiliary(
    k: &Kernel<'_>,
    from: &BTreeSet<Object>,
    to: &BTreeSet<Object>,
    add: bool,
) -> io::Result<()> {
    let mut tables = BTreeMap::<(Family, &str), String>::new();
    for obj in to.difference(from) {
        if !matches!(obj, Object::GroupFirewall(..)) {
            continue;
        }
        let (name, chain, spec) = obj.xtables().unwrap();
        let entries = tables
            .entry((obj.family(), name))
            .or_insert_with(|| format!("*{name}\n"));
        writeln!(
            entries,
            "{} {chain} {}",
            if add { "-A" } else { "-D" },
            spec.join(" ")
        )
        .unwrap();
    }
    for ((f, _), mut doc) in tables {
        doc.push_str("COMMIT\n");
        let tool = if f == Family::V4 {
            "iptables-restore"
        } else {
            "ip6tables-restore"
        };
        k.run
            .run_input(tool, &["--noflush"], doc.as_bytes(), k.deadline)?;
    }
    Ok(())
}
pub(super) fn synchronize(
    k: &Kernel<'_>,
    present: &BTreeSet<Object>,
    target: &BTreeSet<Object>,
) -> io::Result<()> {
    let collect = |objects: &BTreeSet<Object>, marked: bool| {
        objects
            .iter()
            .filter(|o| owned(o) == marked)
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    let old = collect(present, true);
    let new = collect(target, true);
    // Linux removes the unicast route together with its device. The second
    // default must already exist when a marked table first becomes usable.
    for guard in new
        .difference(&old)
        .filter(|o| matches!(o, Object::MarkFence(..)))
    {
        k.mutate(guard, true)?;
    }
    packed::create(k, &old, &new)?;
    auxiliary(k, &old, &new, true)?;
    for obj in new
        .difference(&old)
        .filter(|o| matches!(o, Object::Route(..) | Object::MarkLookup(..)))
    {
        k.mutate(obj, true)?;
    }
    if !new.is_empty() && new != old {
        fence::verify(k, &new)?;
        let sets = packed::inventory(k, &new, &BTreeSet::new())?;
        if new
            .iter()
            .any(|o| matches!(o, Object::Set(..) | Object::SetMember(..)) && !sets.contains(o))
        {
            return Err(err(
                "новые адресные наборы не заполнены перед переключением",
            ));
        }
        for obj in &new {
            let Object::Route(dest, i, t) = obj else {
                continue;
            };
            let slot = (t - 18000) as u8;
            let sample = if dest.family() == Family::V4 {
                "9.9.9.9"
            } else {
                "2620:fe::fe"
            };
            // This is a netlink route lookup, not a transmitted packet.
            let out = k.call(
                "ip",
                &[
                    dest.family().flag(),
                    "route",
                    "get",
                    sample,
                    "mark",
                    &mark(slot),
                ],
            )?;
            if !out
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|p| p == ["dev", i])
            {
                return Err(err("таблица нового маркированного туннеля ещё не готова"));
            }
        }
    }
    // Both sets of targets are now complete. When moving back to an ordinary
    // policy, preinstall its routing before detaching the marked classifier.
    let old_plain = collect(present, false);
    let new_plain = collect(target, false);
    if new.is_empty() {
        super::synchronize_plain(k, &old_plain, &new_plain)?;
    }
    for f in [Family::V4, Family::V6] {
        switch(
            k,
            f,
            generation(&old, f).map(Vec::as_slice).unwrap_or_default(),
            generation(&new, f).map(Vec::as_slice).unwrap_or_default(),
        )?;
    }
    if !new.is_empty() {
        super::synchronize_plain(k, &old_plain, &new_plain)?;
    }
    for obj in old
        .iter()
        .rev()
        .filter(|o| !new.contains(o) && matches!(o, Object::Route(..) | Object::MarkLookup(..)))
    {
        k.mutate(obj, false)?;
    }
    for guard in old
        .difference(&new)
        .filter(|o| matches!(o, Object::MarkFence(..)))
    {
        k.mutate(guard, false)?;
    }
    auxiliary(k, &new, &old, false)?;
    packed::remove_sets(k, &old, &new)
}
pub(super) fn verify(k: &Kernel<'_>, plan: &Plan) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    for (s, primary) in plan.flows() {
        let Some(iface) = plan.effective(s, primary) else {
            continue;
        };
        if !seen.insert((s.dest.family(), iface)) {
            continue;
        }
        let addr = s.dest.sample().to_string();
        let output = k.call(
            "ip",
            &[
                s.dest.family().flag(),
                "route",
                "get",
                &addr,
                "mark",
                &mark(plan.marks[iface]),
            ],
        )?;
        if !output
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["dev", iface])
        {
            return Err(err("ядро выбрало другой интерфейс маркированной зоны"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_replies_and_marked_sockets_bypass_the_classifier_at_either_hook_position() {
        let group = Group {
            token: "g1234567890123456789012".into(),
            source: None,
            slot: 1,
        };
        let r = rules(Family::V4, std::slice::from_ref(&group), "PREROUTING");
        let dns = "-A PREROUTING -m connmark --mark 0x8000d500/0x8000ffff -j N2S_DNS_PRE";
        let chain="-A N2S_DNS_PRE -m mark --mark 0x40000000/0x40000000 -j ACCEPT\n-A N2S_DNS_PRE -p tcp -m connbytes --connbytes 1:32 --connbytes-mode packets --connbytes-dir reply -j NFQUEUE --queue-num 200 --queue-bypass\n-A N2S_DNS_PRE -j ACCEPT";
        let own = r
            .iter()
            .map(|r| format!("-A {r}"))
            .collect::<Vec<_>>()
            .join("\n");
        for line in [format!("{dns}\n{own}"), format!("{own}\n{dns}")] {
            assert_eq!(
                installed(&format!("{line}\n{chain}"), "PREROUTING").unwrap(),
                r
            );
        }
        assert!(installed(&format!("-A PREROUTING -j FOREIGN\n{own}"), "PREROUTING").is_err());
        assert!(installed(
            &format!("{dns}\n{own}\n-A N2S_DNS_PRE -j RETURN"),
            "PREROUTING"
        )
        .is_err());
        let slots = BTreeSet::from([1]);
        assert!(check_rpdb(
            "42: from all fwmark 0x10100000/0x1ff00000 lookup 24",
            &slots,
            false
        )
        .is_err());
        assert!(check_rpdb(
            "71: from all fwmark 0x10100000/0x1ff00000 lookup 901",
            &slots,
            true
        )
        .is_ok());
        for row in [
            "42: from all fwmark 0x10100000/0x1ff00000 lookup 901",
            "72: from all fwmark 0x10100000/0x1ff00000 lookup 902",
        ] {
            assert!(check_rpdb(row, &slots, true).is_err(), "{row}");
        }
        for (parent, spec) in [("OUTPUT", "-m mark !"), ("PREROUTING", "-m connmark !")] {
            for rule in rules(Family::V4, std::slice::from_ref(&group), parent) {
                assert!(rule.contains(&format!("{spec} --mark 0x8000d500/0x8000ff80")));
                assert!(rule.contains("--mark 0x0/0x20000000"));
            }
        }
        for socket in [0x8000d500u32, 0x8000d57f] {
            assert_eq!(socket & 0x8000ff80, 0x8000d500);
        }
        for socket in [0x20000000u32, 0xa0010001] {
            assert_ne!(socket & 0x20000000, 0);
        }
    }
}
