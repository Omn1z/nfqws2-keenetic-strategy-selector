//! Boot-scoped ownership. Each distinct plan is stored once, including in a
//! Go rollback checkpoint. References never expand into independent route maps.
use super::{Plan, LEGACY_PREPARATIONS};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io::{self, Write};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, OnceLock};
pub(super) mod prefixes;
#[cfg(test)]
mod tests;

const MAX_INTENTS: usize = LEGACY_PREPARATIONS + 1;
const MAX_GENERATIONS: usize = MAX_INTENTS + 2;
pub(super) const GENERATION_LIMIT: u64 = 12 << 20;
const TRANSACTION_LIMIT: u64 = 2 * GENERATION_LIMIT;
// Account for decoded rows separately: a compact numeric IPv4 entry is much
// cheaper on flash than its owned BTreeMap node and interface string in RAM.
const GENERATION_ROWS: usize = super::packed::LIMIT;
const TRANSACTION_ROWS: usize = 2 * GENERATION_ROWS;
// Recovery may need one additional guard-only generation. The outer envelope
// is bounded separately by its field types, boot UUID and generation count.
pub(super) const RECEIPT_LIMIT: u64 = TRANSACTION_LIMIT + GENERATION_LIMIT + 16_384;

fn row_count(plan: &Plan) -> usize {
    plan.prefixes.len()
        + plan.scoped.len()
        + plan.selected.len()
        + plan.source_ranges.values().map(Vec::len).sum::<usize>()
        + plan
            .reserves
            .iter()
            .map(|(_, names)| names.len().max(1))
            .sum::<usize>()
        + plan.learned.as_ref().map_or(0, |saved| saved.members.len())
        + plan.legacy_scope.as_ref().map_or(0,super::legacy_scope::Scope::rows)
}

pub(super) fn encoded_size(plan: &Plan) -> io::Result<u64> {
    if row_count(plan) > GENERATION_ROWS {
        return Err(super::err(
            "слишком много развёрнутых записей в поколении маршрутов",
        ));
    }
    #[derive(Default)]
    struct Size(u64);
    impl Write for Size {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 += bytes.len() as u64;
            if self.0 > GENERATION_LIMIT {
                return Err(super::err(
                    "снимок маршрутов превышает предел поколения журнала",
                ));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Size::default();
    serde_json::to_writer(&mut output, plan)?;
    Ok(output.0)
}

#[derive(Clone, Debug, Default)]
struct Generation {
    plan: Plan,
    bytes: OnceLock<u64>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Snapshot(Arc<Generation>);
impl From<Plan> for Snapshot {
    fn from(plan: Plan) -> Self {
        Self(Arc::new(Generation {
            plan,
            bytes: OnceLock::new(),
        }))
    }
}
impl AsRef<Plan> for Snapshot {
    fn as_ref(&self) -> &Plan {
        &self.0.plan
    }
}
impl Deref for Snapshot {
    type Target = Plan;
    fn deref(&self) -> &Plan {
        self.as_ref()
    }
}
impl DerefMut for Snapshot {
    fn deref_mut(&mut self) -> &mut Plan {
        let generation = Arc::make_mut(&mut self.0);
        generation.bytes.take();
        &mut generation.plan
    }
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.as_ref() == other.as_ref()
    }
}
impl Eq for Snapshot {}
impl Snapshot {
    fn size(&self) -> io::Result<u64> {
        if let Some(bytes) = self.0.bytes.get() {
            return Ok(*bytes);
        }
        let bytes = encoded_size(self)?;
        Ok(*self.0.bytes.get_or_init(|| bytes))
    }
}
impl Serialize for Snapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_ref().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Snapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Self::from(Plan::deserialize(deserializer)?);
        value.size().map_err(de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub(super) struct Journal {
    pub(super) boot: String,
    pub(super) installed: Snapshot,
    pub(super) committed: Snapshot,
    pub(super) preparing: Vec<Snapshot>,
    pub(super) expires: u64,
}

impl Journal {
    pub(super) fn unique_generations(&self) -> Vec<&Snapshot> {
        let mut unique = Vec::with_capacity(MAX_GENERATIONS);
        for value in [&self.installed, &self.committed]
            .into_iter()
            .chain(&self.preparing)
        {
            if !unique.contains(&value) {
                unique.push(value);
            }
        }
        unique
    }
    fn check_budget(&self, unique: &[&Snapshot]) -> io::Result<()> {
        if self.preparing.len() > MAX_INTENTS {
            return Err(super::err("слишком много подготовленных поколений"));
        }
        let mut total = 0;
        let mut rows = 0;
        for generation in unique {
            total += generation.size()?;
            rows += row_count(generation);
        }
        if total <= TRANSACTION_LIMIT && rows <= TRANSACTION_ROWS {
            return Ok(());
        }
        // Only the recovery phase can consume the reserved space. Dropping
        // this final intent must put the original transaction back in budget.
        if let Some(last) = self.preparing.last() {
            if last != &self.installed
                && last != &self.committed
                && !self.preparing[..self.preparing.len() - 1].contains(last)
                && total - last.size()? <= TRANSACTION_LIMIT
                && rows - row_count(last) <= TRANSACTION_ROWS
                && last.as_ref() == &self.committed.guards_only()
            {
                return Ok(());
            }
        }
        Err(super::err(
            "поколения превышают общий предел журнала восстановления",
        ))
    }
    pub(super) fn check_size(&self) -> io::Result<()> {
        self.check_budget(&self.unique_generations())
    }
}

#[derive(Serialize)]
struct Indexed<'a> {
    boot: &'a str,
    expires: u64,
    generations: &'a [&'a Snapshot],
    installed: usize,
    committed: usize,
    preparing: Vec<usize>,
}

impl Serialize for Journal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let unique = self.unique_generations();
        self.check_budget(&unique)
            .map_err(serde::ser::Error::custom)?;
        let index = |value: &Snapshot| unique.iter().position(|v| *v == value).unwrap();
        (
            2_u8,
            Indexed {
                boot: &self.boot,
                expires: self.expires,
                generations: &unique,
                installed: index(&self.installed),
                committed: index(&self.committed),
                preparing: self.preparing.iter().map(index).collect(),
            },
        )
            .serialize(serializer)
    }
}

// Apply the count limit while reading, before growing a vector of generations
// or resolving references. No intermediate JSON tree or untagged buffering.
struct Limited<T, const N: usize>(Vec<T>);
pub(super) fn source_ranges<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<std::collections::BTreeMap<super::Prefix, Vec<super::Prefix>>, D::Error> {
    struct Read;
    impl<'de> Visitor<'de> for Read {
        type Value = std::collections::BTreeMap<super::Prefix, Vec<super::Prefix>>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded source classes of routed networks")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut ranges = Self::Value::new();
            let mut total = 0;
            while let Some(key) = map.next_key::<super::Prefix>()? {
                if total >= GENERATION_ROWS || ranges.contains_key(&key) {
                    return Err(de::Error::custom("excessive or duplicate source class"));
                }
                let values = map
                    .next_value::<Limited<super::Prefix, GENERATION_ROWS>>()?
                    .0;
                total += values.len();
                if values.first() != Some(&key) || total > GENERATION_ROWS {
                    return Err(de::Error::custom("invalid or excessive source class"));
                }
                ranges.insert(key, values);
            }
            Ok(ranges)
        }
    }
    d.deserialize_map(Read)
}
pub(super) fn route_rows<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    Limited::<T, { super::packed::LIMIT }>::deserialize(d).map(|rows| rows.0)
}
pub(super) fn reserves<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<(super::plan::Selector, Vec<String>)>, D::Error> {
    type Chain = (
        super::plan::Selector,
        Limited<String, { super::plan::MAX_TARGETS }>,
    );
    let mut count = 0;
    rows::<_, Chain, _, _, { super::packed::LIMIT }>(d, |(selector, names), _| {
        count += names.0.len().max(1);
        if count > GENERATION_ROWS || !names.0.iter().all(|n| super::plan::iface_ok(n)) {
            return Err(super::err("invalid or excessive route failover chains"));
        }
        Ok((selector, names.0))
    })
}
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Limited<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        rows::<_, T, _, _, N>(deserializer, |value, _| Ok(value)).map(Self)
    }
}
fn rows<'de, D, T, U, F, const N: usize>(deserializer: D, row: F) -> Result<Vec<U>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
    F: FnMut(T, &[U]) -> io::Result<U>,
{
    struct Rows<T, U, F, const N: usize>(F, std::marker::PhantomData<fn(T) -> U>);
    impl<'de, T: Deserialize<'de>, U, F: FnMut(T, &[U]) -> io::Result<U>, const N: usize>
        Visitor<'de> for Rows<T, U, F, N>
    {
        type Value = Vec<U>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "at most {N} entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while values.len() < N {
                let Some(value) = seq.next_element()? else {
                    return Ok(values);
                };
                let value = (self.0)(value, &values).map_err(de::Error::custom)?;
                values.push(value);
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::invalid_length(N + 1, &self));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Rows::<T, U, F, N>(row, std::marker::PhantomData))
}
fn definitions<'de, D: Deserializer<'de>, const LEGACY: bool, const N: usize>(
    d: D,
) -> Result<Vec<Snapshot>, D::Error> {
    let mut entries = 0;
    let mut bytes = 0;
    rows::<_, Snapshot, Snapshot, _, N>(d, |value, seen| {
        if let Some(equal) = seen.iter().find(|p| *p == &value) {
            if LEGACY {
                return Ok(equal.clone());
            }
            return Err(super::err("duplicate route generation"));
        }
        entries += row_count(&value);
        bytes += value.size()?;
        if entries > TRANSACTION_ROWS + GENERATION_ROWS
            || bytes > TRANSACTION_LIMIT + GENERATION_LIMIT
        {
            return Err(super::err("route generations exceed recovery limits"));
        }
        Ok(value)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexedRead {
    boot: String,
    expires: u64,
    #[serde(deserialize_with = "definitions::<_, false, MAX_GENERATIONS>")]
    generations: Vec<Snapshot>,
    installed: usize,
    committed: usize,
    preparing: Limited<usize, MAX_INTENTS>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    boot: String,
    installed: Snapshot,
    committed: Snapshot,
    #[serde(deserialize_with = "definitions::<_, true, MAX_INTENTS>")]
    preparing: Vec<Snapshot>,
    expires: u64,
}

impl<'de> Deserialize<'de> for Journal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Read;
        impl<'de> Visitor<'de> for Read {
            type Value = Journal;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a versioned route journal or a legacy receipt")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Journal, A::Error> {
                let old = Legacy::deserialize(de::value::MapAccessDeserializer::new(map))?;
                // The legacy writer always used an 8 MiB envelope. Its map
                // encoding of prefixes was at least as long as the run form.
                let legacy_bytes = [&old.installed, &old.committed]
                    .into_iter()
                    .chain(&old.preparing)
                    .try_fold(0_u64, |sum, p| p.size().map(|n| sum + n))
                    .map_err(de::Error::custom)?;
                if legacy_bytes > 8 << 20 {
                    return Err(de::Error::custom("legacy route receipt exceeds its limit"));
                }
                let mut known = Vec::<Snapshot>::new();
                let mut intern = |value: Snapshot| {
                    if let Some(i) = known.iter().position(|v| v == &value) {
                        return known[i].clone();
                    }
                    known.push(value.clone());
                    value
                };
                let journal = Journal {
                    boot: old.boot,
                    expires: old.expires,
                    installed: intern(old.installed),
                    committed: intern(old.committed),
                    preparing: old.preparing.into_iter().map(intern).collect(),
                };
                journal.check_size().map_err(de::Error::custom)?;
                Ok(journal)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Journal, A::Error> {
                if seq.next_element::<u8>()? != Some(2) {
                    return Err(de::Error::custom("unsupported route journal version"));
                }
                let indexed: IndexedRead = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(3, &self));
                }
                let plans = indexed.generations;
                // Require exactly one definition for each referenced generation.
                let mut used = [false; MAX_GENERATIONS];
                let mut get = |i: usize| {
                    let value = plans
                        .get(i)
                        .ok_or_else(|| de::Error::custom("unknown route generation"))?;
                    used[i] = true;
                    Ok::<_, A::Error>(value.clone())
                };
                let journal = Journal {
                    boot: indexed.boot,
                    expires: indexed.expires,
                    installed: get(indexed.installed)?,
                    committed: get(indexed.committed)?,
                    preparing: indexed
                        .preparing
                        .0
                        .into_iter()
                        .map(get)
                        .collect::<Result<_, _>>()?,
                };
                if used[..plans.len()].contains(&false) {
                    return Err(de::Error::custom("unreferenced route generation"));
                }
                journal
                    .check_budget(&plans.iter().collect::<Vec<_>>())
                    .map_err(de::Error::custom)?;
                Ok(journal)
            }
        }
        deserializer.deserialize_any(Read)
    }
}
