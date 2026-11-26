//! Persistent, observational route history shared with existing installations.
use super::{
    identity::digest,
    model::{err, hostname},
    policy, Zone,
};
use crate::observed::Scope;
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};
const LIMIT: usize = 4096;
const RULE_LIMIT: usize = 512;
const FILE_LIMIT: u64 = 32 << 20;
pub const FILE: &str = "awg-routing-learned.json";
mod recent;
pub use recent::Recent;
#[derive(Serialize)]
struct Identity<'a> {
    route: &'a str,
    tunnel_id: &'a str,
    fallback_tunnel_ids: Vec<String>,
    domains: Vec<String>,
    include_subdomains: Option<bool>,
    ips: Vec<String>,
    source_ips: Vec<String>,
    waiting_for_connection: bool,
}
fn items(values: &[String], sorted: bool, domains: bool) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut items: Vec<_> = values
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if !sorted {
                return s.to_string();
            }
            let lower = s.to_lowercase();
            if domains {
                for prefix in ["list:", "geosite:", "geoip:"] {
                    if lower.starts_with(prefix) {
                        return format!("{prefix}{}", s[prefix.len()..].trim());
                    }
                }
            }
            lower
        })
        .filter(|s| seen.insert(s.clone()))
        .collect();
    if sorted {
        items.sort_unstable();
    }
    items
}
pub fn rule_key(z: &Zone) -> io::Result<String> {
    if let Some(key) = &z.source_key {
        return Ok(key.clone());
    }
    let id = Identity {
        route: z.direction(),
        tunnel_id: z.tunnel_id.trim(),
        fallback_tunnel_ids: items(&z.fallback_tunnel_ids, false, false),
        domains: items(&z.domains, true, true),
        include_subdomains: z.include_subdomains,
        ips: items(&z.ips, true, false),
        source_ips: items(&z.source_ips, true, false),
        waiting_for_connection: z.waiting_for_connection,
    };
    let go = serde_json::to_string(&id)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    Ok(digest(go.as_bytes(), 32))
}
#[derive(Deserialize, Default)]
struct Document {
    version: u8,
    #[serde(deserialize_with = "read_entries")]
    entries: Vec<Entry>,
}
fn read_entries<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Entry>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<Entry>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("до 4096 записей истории")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut input: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            while let Some(entry) = input.next_element()? {
                if entries.len() == LIMIT {
                    return Err(serde::de::Error::custom("превышен размер истории"));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }
    d.deserialize_seq(Visitor)
}
#[derive(Serialize, Deserialize)]
struct Entry {
    #[serde(skip_serializing)]
    rule_key: String,
    domain: String,
    ips: Vec<String>,
    source_ips: Option<Vec<String>>,
    source: String,
    first_seen: i64,
    last_seen: i64,
    additional: bool,
    #[serde(skip_deserializing)]
    confirmed: bool,
}

#[cfg(test)]
mod tests;
fn ips(raw: &[String], limit: usize) -> Vec<String> {
    let mut addresses = Vec::new();
    for s in raw {
        if let Ok(ip) = s.trim().parse::<IpAddr>() {
            let ip = ip.to_canonical();
            let s = ip.to_string();
            if !ip.is_unspecified() && !addresses.contains(&s) {
                addresses.push(s);
            }
        }
        if addresses.len() == limit {
            break;
        }
    }
    addresses.sort_unstable();
    addresses
}
#[derive(Serialize)]
struct Row {
    rule_index: usize,
    rule_key: String,
    rule: Zone,
    entries: Arc<[Entry]>,
}
#[derive(Serialize)]
pub struct Snapshot {
    revision: u64,
    active: bool,
    ready: bool,
    domain_source: String,
    rules: Vec<Row>,
    limit: usize,
}
impl Document {
    fn checked(self) -> io::Result<Vec<Entry>> {
        if self.version != 1 || self.entries.len() > LIMIT {
            return Err(err("неверная версия или размер истории маршрутов"));
        }
        Ok(self.entries)
    }
}
pub fn validate_file(path: &std::path::Path) -> io::Result<()> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > FILE_LIMIT {
        return Err(err("превышен размер истории маршрутов"));
    }
    let mut bounded = file.take(FILE_LIMIT + 1);
    let doc: Document = serde_json::from_reader(io::BufReader::new(&mut bounded))?;
    if bounded.limit() == 0 {
        return Err(err("превышен размер истории маршрутов"));
    }
    doc.checked().map(drop)
}
fn load_groups(db: &Store) -> io::Result<HashMap<String, Vec<Entry>>> {
    let saved = match db.read_limited::<Document>(FILE, FILE_LIMIT) {
        Ok(d) => d.checked()?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let mut grouped: HashMap<String, Vec<Entry>> = HashMap::new();
    for mut e in saved {
        e.domain = e.domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if e.rule_key.is_empty()
            || e.rule_key.len() > 128
            || e.last_seen <= 0
            || !matches!(e.source.as_str(), "dns" | "sni")
            || !hostname(&e.domain)
        {
            continue;
        }
        e.ips = ips(&e.ips, 64);
        if e.ips.is_empty() {
            continue;
        }
        e.source_ips = Some(ips(e.source_ips.as_deref().unwrap_or_default(), 8));
        e.first_seen = if e.first_seen > 0 {
            e.first_seen.min(e.last_seen)
        } else {
            e.last_seen
        };
        grouped
            .entry(std::mem::take(&mut e.rule_key))
            .or_default()
            .push(e);
    }
    Ok(grouped)
}
fn trim(groups: &mut HashMap<String, Vec<Entry>>) {
    for rows in groups.values_mut() {
        rows.sort_unstable_by(|a, b| a.domain.cmp(&b.domain).then(b.last_seen.cmp(&a.last_seen)));
        rows.dedup_by(|a, b| a.domain == b.domain);
        rows.sort_unstable_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.domain.cmp(&b.domain)));
        rows.truncate(RULE_LIMIT);
    }
    if groups.values().map(Vec::len).sum::<usize>() > LIMIT {
        // Full Go journal plus new session observations. Keep the newest
        // global entries using the same limit the endpoint advertises.
        let mut ranking: Vec<_> = groups
            .iter()
            .flat_map(|(key, rows)| {
                rows.iter()
                    .map(move |e| (e.last_seen, key.as_str(), e.domain.as_str()))
            })
            .collect();
        let cutoff = ranking.len() - LIMIT;
        let &mut (last_seen, key, name) = ranking.select_nth_unstable(cutoff).1;
        let (key, name) = (key.to_owned(), name.to_owned());
        for (rule, rows) in groups {
            rows.retain(|e| {
                (e.last_seen, rule.as_str(), e.domain.as_str())
                    >= (last_seen, key.as_str(), name.as_str())
            });
        }
    }
}
pub fn snapshot(
    db: &Store,
    resolve: impl Fn(&str, &str) -> io::Result<Vec<String>>,
    active: bool,
    ready: bool,
    revision: u64,
    recent: &Recent,
) -> io::Result<Snapshot> {
    let cfg = policy::current(&nfqws2_awg_profile::read(db)?)?;
    let mut grouped = load_groups(db)?;
    recent.merge(&mut grouped, active && ready, revision);
    trim(&mut grouped);
    let mut rows = Vec::with_capacity(cfg.zones.len());
    let mut cache: HashMap<String, Arc<[Entry]>> = HashMap::new();
    for (i, z) in cfg.zones.into_iter().enumerate() {
        let k = rule_key(&z)?;
        if let Some(entries) = cache.get(&k) {
            rows.push(Row {
                rule_index: i,
                rule_key: k,
                rule: z,
                entries: entries.clone(),
            });
            continue;
        }
        let mut entries = Vec::new();
        let catchall = z.domains.iter().any(|s| s.trim() == "*")
            || z.ips
                .iter()
                .any(|s| matches!(s.trim(), "0.0.0.0/0" | "::/0"));
        if let Some(history) = grouped.remove(&k).filter(|_| !catchall) {
            let mut scope = Scope::default();
            let mut total = 0usize;
            for d in &z.domains {
                let (kind, name) = d.trim().split_once(':').unwrap_or(("", ""));
                let kind = kind.to_ascii_lowercase();
                if matches!(kind.as_str(), "list" | "geosite" | "geoip") {
                    if kind != "geoip" {
                        let lines = match resolve(&kind, name.trim()) {
                            Ok(v) => v,
                            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                            Err(e) => return Err(e),
                        };
                        for s in lines {
                            if crate::model::ipish(&s) {
                                continue;
                            }
                            total += s.len();
                            if total > crate::sources::MAX_SOURCE_BYTES {
                                return Err(err("списки одного правила превышают 4 МиБ"));
                            }
                            scope.add_history(&s, z.include_subdomains)?;
                        }
                    }
                } else {
                    scope.add_history(d, z.include_subdomains)?;
                }
            }
            for mut e in history {
                if let Some(additional) = scope.match_domain(&e.domain) {
                    e.additional = additional;
                    entries.push(e);
                }
            }
            entries.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.domain.cmp(&b.domain)));
        }
        let entries: Arc<[Entry]> = entries.into();
        cache.insert(k.clone(), entries.clone());
        rows.push(Row {
            rule_index: i,
            rule_key: k,
            rule: z,
            entries,
        });
    }
    Ok(Snapshot {
        revision,
        active,
        ready,
        domain_source: cfg.domain_source,
        rules: rows,
        limit: LIMIT,
    })
}
