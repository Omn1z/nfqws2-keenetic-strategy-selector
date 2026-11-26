use crate::kernel::{err, inventory, plan::Family, Kernel, Object};
use std::{collections::BTreeSet, io};

const LIST: &[&str] = &["-s", "-t", "list", "ruleset"];

struct Chain<'a> {
    family: Family,
    table: &'a str,
    name: &'a str,
    length: usize,
    opaque: Vec<(usize, bool)>,
}

/// iptables-nft can hide an xt comment's literal value in its raw nft view.
/// Recover only a native rule at the same ordinal in the same kernel chain,
/// with an exact normalized key in the already-installed trial receipt.
pub(in crate::kernel) fn verify(k: &Kernel<'_>, claims: &BTreeSet<Object>) -> io::Result<()> {
    let missing = || err("не подтверждено правило nft активного пробного переноса AWG");
    let first = k.call("nft", LIST)?;
    let mut table = None;
    let mut chain: Option<Chain<'_>> = None;
    let mut verified = false;
    for line in first.lines() {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        let looks_old = inventory::go_firewall(line);
        match words.as_slice() {
            ["table", family, name @ ("mangle" | "filter" | "nat"), "{"] => {
                table = match *family {
                    "ip" => Some((Family::V4, *name)),
                    "ip6" => Some((Family::V6, *name)),
                    _ => None,
                };
            }
            ["table", ..] => table = None,
            ["chain", name, "{"] => {
                chain = table.map(|(family, table)| Chain {
                    family,
                    table,
                    name,
                    length: 0,
                    opaque: Vec::new(),
                });
            }
            ["}"] => {
                if let Some(closed) = chain.take().filter(|closed| !closed.opaque.is_empty()) {
                    verify_chain(k, claims, &closed)?;
                    verified = true;
                }
                if line == "}" {
                    table = None;
                }
            }
            ["type" | "policy", ..] | [] if !looks_old => (),
            _ => {
                if let Some(current) = &mut chain {
                    if line.contains("xt match \"comment\"") {
                        current.opaque.push((current.length, looks_old));
                    } else if looks_old {
                        return Err(missing());
                    }
                    current.length += 1;
                } else if looks_old {
                    return Err(missing());
                }
                continue;
            }
        }
        if looks_old {
            return Err(missing());
        }
    }
    if chain.is_some() || verified && k.call("nft", LIST)? != first {
        return Err(missing());
    }
    Ok(())
}

fn verify_chain(k: &Kernel<'_>, claims: &BTreeSet<Object>, chain: &Chain<'_>) -> io::Result<()> {
    let missing = || err("не совпало подтверждённое правило iptables-nft AWG");
    let tool = match chain.family {
        Family::V4 => "iptables-nft",
        Family::V6 => "ip6tables-nft",
    };
    let decoded = k.call(tool, &["-w", "-t", chain.table, "-S", chain.name])?;
    if inventory::go_firewall(&decoded) {
        return Err(missing());
    }
    let mut declaration = false;
    let mut actual = Vec::new();
    for line in decoded.lines() {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["-P", name, "ACCEPT" | "DROP"] | ["-N", name]
                if !declaration && *name == chain.name =>
            {
                declaration = true;
            }
            ["-A", name, _, ..] if declaration && *name == chain.name => {
                actual.push(inventory::normalize_firewall_rule(chain.family, line));
            }
            _ => return Err(missing()),
        }
    }
    let expected: BTreeSet<_> = claims
        .iter()
        .filter(|object| object.family() == chain.family)
        .filter_map(Object::xtables)
        .filter_map(|(table, name, spec)| {
            (table == chain.table && name == chain.name)
                .then(|| format!("-A {name} {}", spec.join(" ")))
        })
        .collect();
    if !declaration || actual.len() != chain.length {
        return Err(missing());
    }
    let mut accounted = BTreeSet::new();
    for &(index, looks_old) in &chain.opaque {
        let value = &actual[index];
        let native_tag = value
            .split_once(" --comment ")
            .and_then(|(_, tail)| tail.split_ascii_whitespace().next())
            == Some(inventory::TAG);
        if (looks_old || native_tag) && (!expected.contains(value) || !accounted.insert(value)) {
            return Err(missing());
        }
    }
    Ok(())
}
