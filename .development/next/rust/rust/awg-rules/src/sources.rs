//! Resolve local zone references without replacing them in awg.json.
use crate::{
    model::{dependency, domain, err, ipish, ROUTING_ENTRY_LIMIT},
    policy, Routing,
};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io,
};

const FILE: &str = "awg-routing-sources.json";
const LIMIT: u64 = 20 << 20;
const TOTAL_SOURCE_BYTES: usize = 12 << 20;
pub const MAX_SOURCE_BYTES: usize = 4 << 20;
pub const MAX_SOURCE_ENTRIES: usize = 100_000;
type Sources = BTreeMap<String, Vec<String>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Generation {
    draft: String,
    content: String,
}
impl Generation {
    pub(crate) fn from_policy(doc: &Value, effective: &Routing) -> io::Result<Option<Self>> {
        if !effective.zones.iter().any(|z| z.source_key.is_some()) {
            return Ok(None);
        }
        let raw = policy::current(doc)?;
        let refs = crate::identity::refs(doc, &crate::identity::live(doc))?;
        Ok(Some(Self {
            draft: policy::policy_hash(&raw, &refs),
            content: policy::policy_hash(effective, &refs),
        }))
    }
    pub(crate) fn can_replace(&self, newer: &Self) -> bool {
        self.draft == newer.draft && self.content != newer.content
    }
}

fn references(r: &Routing) -> BTreeSet<&str> {
    r.zones
        .iter()
        .filter(|z| z.enabled && !z.waiting_for_connection && r.mode != "off")
        .flat_map(|z| &z.domains)
        .map(String::as_str)
        .filter(|v| dependency(v).is_some())
        .collect()
}

fn snapshot(db: &Store) -> io::Result<Option<Sources>> {
    match db.read_runtime(FILE, LIMIT) {
        Ok(values) => Ok(Some(values)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

// Keep only a bounded fingerprint while performing lookups. BTreeMap order and
// the length prefixes distinguish every key, entry and sequence boundary.
fn fingerprint(sources: &Sources) -> [u8; 32] {
    let mut hash = Sha256::new();
    for (key, entries) in sources {
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key.as_bytes());
        hash.update((entries.len() as u64).to_be_bytes());
        for entry in entries {
            hash.update((entry.len() as u64).to_be_bytes());
            hash.update(entry.as_bytes());
        }
    }
    hash.finalize().into()
}

/// Resolve each source outside the store lock. Compare both the references
/// and the source snapshot before publishing a potentially slow lookup.
pub fn stage(
    db: &Store,
    mut lookup: impl FnMut(&str, &str) -> io::Result<Vec<String>>,
) -> io::Result<()> {
    let config = policy::current(&nfqws2_awg_profile::read(db)?)?;
    let keys = references(&config);
    if keys.is_empty() {
        return Ok(());
    }
    let initial = snapshot(db)?.as_ref().map(fingerprint);
    let mut sources = Sources::new();
    let mut bytes = 0usize;
    let mut count = 0usize;
    for key in &keys {
        let (kind, name) = dependency(key).unwrap();
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        let mut source_bytes = 0;
        for line in lookup(kind, name)? {
            let value = line.trim();
            if value.is_empty() || !seen.insert(value.to_owned()) {
                continue;
            }
            domain(value, false)?;
            count += 1;
            bytes += value.len();
            source_bytes += value.len();
            if count > ROUTING_ENTRY_LIMIT
                || bytes > TOTAL_SOURCE_BYTES
                || source_bytes > MAX_SOURCE_BYTES
                || entries.len() >= MAX_SOURCE_ENTRIES
            {
                return Err(err("источники зон превышают допустимый размер"));
            }
            entries.push(value.to_owned());
        }
        sources.insert((*key).to_owned(), entries);
    }
    db.transaction(|tx| {
        let current = policy::current(&nfqws2_awg_profile::read(db)?)?;
        if references(&current) != keys {
            return Err(err("состав источников зон изменился"));
        }
        let published = snapshot(db)?;
        if published.as_ref() == Some(&sources) {
            return Ok(());
        }
        if published.as_ref().map(fingerprint) != initial {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "источники зон уже обновлены другим запросом",
            ));
        }
        tx.save_runtime_bounded(FILE, &sources, LIMIT)
    })
}

// The caller keeps the original policy for the editor, Go witness, and history.
pub(crate) fn expand(db: &Store, mut config: Routing) -> io::Result<Routing> {
    if references(&config).is_empty() {
        return Ok(config);
    }
    let values: Sources = db.read_runtime(FILE, LIMIT)?;
    let mut total = 0usize;
    for zone in config
        .zones
        .iter_mut()
        .filter(|z| z.enabled && !z.waiting_for_connection)
    {
        if !zone.domains.iter().any(|raw| dependency(raw).is_some()) {
            continue;
        }
        zone.source_key = Some(crate::discoveries::rule_key(zone)?);
        let mut seen: HashSet<String> = zone.ips.iter().cloned().collect();
        for raw in std::mem::take(&mut zone.domains) {
            let entries = if dependency(&raw).is_some() {
                values
                    .get(&raw)
                    .ok_or_else(|| err("изменился источник зоны, повторите применение"))?
                    .as_slice()
            } else {
                std::slice::from_ref(&raw)
            };
            for value in entries {
                if !seen.insert(value.clone()) {
                    continue;
                }
                total += 1;
                if total > ROUTING_ENTRY_LIMIT {
                    return Err(err("слишком много записей в правилах"));
                }
                if ipish(value) {
                    zone.ips.push(value.clone())
                } else {
                    zone.domains.push(value.clone())
                }
            }
        }
    }
    config.validate(true)?;
    Ok(config)
}

pub(crate) fn current(db: &Store, doc: &Value) -> io::Result<Routing> {
    expand(db, policy::current(doc)?)
}

#[cfg(test)]
#[test]
fn expands_four_full_go_ip_lists_without_losing_zone_references() {
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let zone_size = ROUTING_ENTRY_LIMIT / 4;
    let zones = (0..4)
        .map(|index| {
            json!({
                "name":format!("zone {index}"), "route":"tunnel", "enabled":true,
                "domains":[format!("list:{index}")]
            })
        })
        .collect::<Vec<_>>();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"] = json!({"mode":"zones"});
        doc["servers"][0]["config"]["routing"] = json!({"mode":"zones","zones":zones});
        Ok(())
    })
    .unwrap();
    stage(&db, |kind, name| {
        assert_eq!(kind, "list");
        let zone: u16 = name.parse().unwrap();
        Ok((0..zone_size)
            .map(|index| format!("2001:db8:{zone:x}:{index:x}::/64"))
            .collect())
    })
    .unwrap();
    let document = nfqws2_awg_profile::read(&db).unwrap();
    let draft = policy::current(&document).unwrap();
    let effective = current(&db, &document).unwrap();
    for (index, zone) in effective.zones.iter().enumerate() {
        assert_eq!(zone.ips.len(), zone_size);
        assert!(zone.domains.is_empty());
        assert_eq!(draft.zones[index].domains, [format!("list:{index}")]);
    }
}
