use super::{err, evidence, Kernel, Saved};
use std::{collections::BTreeSet, fmt::Write, io};

const PARENTS: [&str; 3] = ["PREROUTING", "FORWARD", "POSTROUTING"];
const TABLES: [(&str, &str); 2] = [
    ("iptables-save", "iptables-restore"),
    ("ip6tables-save", "ip6tables-restore"),
];
fn chains(id: &str) -> [String; 3] {
    ["I", "F", "O"].map(|v| format!("N2RP{v}_{id}"))
}
fn contents(ch: &str, index: usize, tag: &str, ifaces: &[String]) -> Vec<String> {
    let end = format!("-m comment --comment {tag} -j PPE");
    let mut rules = Vec::new();
    for dir in ["original", "reply"] {
        rules.push(format!("-A {ch} -m connbytes --connbytes 1:32 --connbytes-mode packets --connbytes-dir {dir} {end}"));
    }
    for f in ["SYN", "FIN", "RST"] {
        rules.push(format!("-A {ch} -p tcp -m tcp --tcp-flags {f} {f} {end}"));
    }
    for iface in ifaces {
        if index != 2 {
            rules.push(format!("-A {ch} -i {iface} {end}"));
        }
        if index != 0 {
            rules.push(format!("-A {ch} -o {iface} {end}"));
        }
    }
    rules
}
fn canon(line: &str) -> String {
    let mut items: Vec<_> = line
        .split_ascii_whitespace()
        .map(|t| t.trim_matches('"'))
        .collect();
    if let Some(i) = items.iter().position(|v| *v == "--tcp-flags") {
        for flag in items.iter_mut().skip(i + 1).take(2) {
            *flag = match *flag {
                "0x01" | "0x1" => "FIN",
                "0x02" | "0x2" => "SYN",
                "0x04" | "0x4" => "RST",
                v => v,
            };
        }
    }
    items.join(" ")
}
#[derive(Default)]
struct Snapshot {
    chains: BTreeSet<String>,
    rules: [Vec<String>; 3],
    jumps: [Vec<(usize, String)>; 3],
}
fn parse(raw: &str, saved: &Saved) -> io::Result<Snapshot> {
    let ids = chains(&saved.id);
    let tag = format!("n2s-ppe-{}", saved.id);
    let mut state = Snapshot::default();
    let mut inside = None;
    let mut complete = false;
    let mut position = [0; 3];
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if let Some(table) = line.strip_prefix('*') {
            if inside.is_some() || (table == "mangle" && complete) {
                return Err(err("повреждён снимок firewall PPE"));
            }
            inside = Some(table);
            continue;
        }
        if line == "COMMIT" {
            complete |= inside.take() == Some("mangle");
            continue;
        }
        if inside != Some("mangle") {
            continue;
        }
        let norm = canon(line);
        let w: Vec<_> = norm.split_whitespace().collect();
        if let Some(name) = w.first().and_then(|s| s.strip_prefix(':')) {
            if ids.iter().any(|id| id == name) && !state.chains.insert(name.into()) {
                return Err(err("повтор цепочки PPE"));
            }
            continue;
        }
        if w.first() != Some(&"-A") || w.len() < 3 {
            return Err(err("неизвестная строка таблицы mangle"));
        }
        if let Some(i) = PARENTS.iter().position(|p| *p == w[1]) {
            position[i] += 1;
        }
        if let Some(i) = ids.iter().position(|p| p == w[1]) {
            let iface = w
                .iter()
                .position(|v| matches!(*v, "-i" | "-o"))
                .and_then(|j| w.get(j + 1))
                .filter(|v| super::super::plan::iface_ok(v));
            let allowed = contents(
                &ids[i],
                i,
                &tag,
                &iface.into_iter().map(|v| (*v).into()).collect::<Vec<_>>(),
            );
            if !allowed.contains(&norm) {
                return Err(err("содержимое цепочки PPE изменено другим владельцем"));
            }
            state.rules[i].push(norm);
        } else if let Some(i) = ids.iter().position(|id| w.iter().any(|v| v == id)) {
            let expected = format!("-A {} -m comment --comment {tag} -j {}", PARENTS[i], ids[i]);
            if norm != expected {
                return Err(err("найдена чужая ссылка на цепочку PPE"));
            }
            state.jumps[i].push((position[i], norm));
        }
    }
    if !complete || inside.is_some() {
        return Err(err("неполный снимок mangle для PPE"));
    }
    Ok(state)
}
fn matches(state: &Snapshot, saved: &Saved, ifaces: &[String]) -> bool {
    let ids = chains(&saved.id);
    let tag = format!("n2s-ppe-{}", saved.id);
    (0..3).all(|i| {
        state.chains.contains(&ids[i])
            && state.rules[i] == contents(&ids[i], i, &tag, ifaces)
            && state.jumps[i].len() == 1
            && state.jumps[i][0].0 == 1
    })
}
fn patch(state: &Snapshot, saved: &Saved, ifaces: Option<&[String]>) -> String {
    let names = chains(&saved.id);
    let tag = format!("n2s-ppe-{}", saved.id);
    let mut doc = String::from("*mangle\n");
    for (i, ch) in names.iter().enumerate() {
        for (_, jump) in &state.jumps[i] {
            writeln!(doc, "-D {}", &jump[3..]).unwrap();
        }
        if state.chains.contains(ch) {
            for owned in &state.rules[i] {
                writeln!(doc, "-D {}", &owned[3..]).unwrap();
            }
            if ifaces.is_none() {
                writeln!(doc, "-X {ch}").unwrap();
            }
        } else if ifaces.is_some() {
            writeln!(doc, "-N {ch}").unwrap();
        }
        if let Some(ifaces) = ifaces {
            for rule in contents(ch, i, &tag, ifaces) {
                writeln!(doc, "{rule}").unwrap();
            }
            writeln!(
                doc,
                "-I {} 1 -m comment --comment {tag} -j {ch}",
                PARENTS[i]
            )
            .unwrap();
        }
    }
    doc.push_str("COMMIT\n");
    doc
}
fn active_set(ifaces: &[String]) -> io::Result<()> {
    if ifaces.is_empty()
        || ifaces.len() > super::super::plan::MAX_TARGETS
        || !ifaces.iter().all(|i| super::super::plan::iface_ok(i))
    {
        return Err(err("не подтверждён состав интерфейсов AWG для PPE"));
    }
    Ok(())
}
pub(super) fn available(k: &Kernel<'_>, saved: &Saved) -> io::Result<bool> {
    for (tool, _) in TABLES {
        let xt = tool.strip_suffix("-save").unwrap();
        k.call(xt, &["-w", "-t", "mangle", "-S"])?;
        let raw = k.call(tool, &[])?;
        let state = parse(&raw, saved)?;
        if !state.chains.is_empty()
            || state.jumps.iter().any(|j| !j.is_empty())
            || !evidence::nfqueue_safe(&raw)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(super) fn synchronize(
    k: &Kernel<'_>,
    saved: &Saved,
    ifaces: Option<&[String]>,
) -> io::Result<()> {
    if let Some(ifaces) = ifaces {
        active_set(ifaces)?;
    }
    for (tool, restore) in TABLES {
        // Loading mangle is needed before the first iptables-save on some vendor kernels.
        let xt = tool.strip_suffix("-save").unwrap();
        k.call(xt, &["-w", "-t", "mangle", "-S"])?;
        let raw = k.call(tool, &[])?;
        let snap = parse(&raw, saved)?;
        if ifaces.is_some_and(|v| matches(&snap, saved, v))
            || ifaces.is_none() && snap.chains.is_empty() && snap.jumps.iter().all(Vec::is_empty)
        {
            continue;
        }
        let update = patch(&snap, saved, ifaces);
        k.run
            .run_input(restore, &["--noflush"], update.as_bytes(), k.deadline)?;
        let verified = parse(&k.call(tool, &[])?, saved)?;
        if !ifaces.map_or_else(
            || verified.chains.is_empty() && verified.jumps.iter().all(Vec::is_empty),
            |v| matches(&verified, saved, v),
        ) {
            return Err(err("ядро не подтвердило цепочки ускорения"));
        }
    }
    Ok(())
}
pub(super) fn intact(k: &Kernel<'_>, saved: &Saved, ifaces: &[String]) -> io::Result<bool> {
    active_set(ifaces)?;
    if !capable(k)? {
        return Ok(false);
    }
    for (tool, _) in TABLES {
        let raw = k.call(tool, &[])?;
        if !matches(&parse(&raw, saved)?, saved, ifaces) || !evidence::nfqueue_safe(&raw) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn capable(k: &Kernel<'_>) -> io::Result<bool> {
    const DEVICE: &str = r#"set -eu
test -r /proc/device-tree/compatible || exit 0
model=$(tr '\000' '\n' </proc/device-tree/compatible)
printf '%s\n' "$model" | grep -qx keenetic,kn-1012 || exit 0
printf '%s\n' "$model" | grep -qx mediatek,mt7981 || exit 0
if test -e /proc/sys/net/netfilter/nf_conntrack_acct; then
  test "$(cat /proc/sys/net/netfilter/nf_conntrack_acct)" = 1 && echo enabled
else
  for f in /proc/net/nf_conntrack /proc/net/ip_conntrack; do
    if test -r "$f"; then printf 'counters\n'; head -c 65536 "$f"; echo END; exit; fi
  done
fi"#;
    let s = k.call("sh", &["-c", DEVICE])?;
    Ok(s == "enabled"
        || s.strip_prefix("counters\n")
            .and_then(|v| v.strip_suffix("END"))
            .is_some_and(|v| evidence::accounting(v.as_bytes())))
}
