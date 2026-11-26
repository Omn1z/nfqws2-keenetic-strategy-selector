use crate::{
    identity::{digest, live, refs, Ref, Refs},
    model::{dependency, domain, err, ipish, text},
    policy::{current, policy_hash, write},
    Routing,
};
use nfqws2_awg_profile::{edit_document, read};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue, Value};
use std::{
    collections::{BTreeMap, HashSet},
    io,
    sync::Arc,
};
pub const FILE_LIMIT: usize = 2 << 20;
const FORMAT: &str = "nfqws2-strategy-routing";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub format: String,
    pub version: u32,
    pub routing: Routing,
    pub connections: Vec<Ref>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}
impl Document {
    fn parse(raw: &RawValue) -> io::Result<Self> {
        let data;
        let bytes = if raw.get().starts_with('"') {
            data = serde_json::from_str::<String>(raw.get())?;
            data.as_bytes()
        } else {
            raw.get().as_bytes()
        };
        let doc: Self = crate::decode(bytes, FILE_LIMIT)?;
        #[derive(Deserialize)]
        struct Shape {
            routing: Zones,
        }
        #[derive(Deserialize)]
        struct Zones {
            zones: Vec<serde::de::IgnoredAny>,
        }
        let shape: Shape =
            serde_json::from_slice(bytes).map_err(|_| err("routing.zones должен быть массивом"))?;
        debug_assert_eq!(doc.routing.zones.len(), shape.routing.zones.len());
        doc.validate()?;
        Ok(doc)
    }
    fn validate(&self) -> io::Result<()> {
        if self.format != FORMAT
            || self.version != 1
            || self.connections.len() > 256
            || self.warnings.len() > 32
            || self.warnings.iter().any(|s| !text(s, 1024))
        {
            return Err(err("неподдерживаемая версия или формат правил"));
        }
        self.routing.validate(false)?;
        let mut known = HashSet::new();
        for r in &self.connections {
            r.validate()?;
            if !known.insert(&r.id) {
                return Err(err("повторяющаяся ссылка подключения"));
            }
        }
        for z in &self.routing.zones {
            if std::iter::once(&z.tunnel_id)
                .chain(&z.fallback_tunnel_ids)
                .any(|id| !known.contains(id))
            {
                return Err(err("правило ссылается на неизвестное подключение"));
            }
        }
        Ok(())
    }
}
pub fn export(
    db: &Store,
    draft: Option<Routing>,
    mut lookup: impl FnMut(&str, &str) -> io::Result<Vec<String>>,
) -> io::Result<Document> {
    let state = read(db)?;
    let live = live(&state);
    let identities = refs(&state, &live)?;
    let mut routing = if let Some(d) = draft {
        d
    } else {
        current(&state)?
    };
    routing.validate(true)?;
    let mut sources = BTreeMap::new();
    let mut count = 0;
    let mut size = 0;
    let mut connections = Vec::new();
    let mut used = HashSet::new();
    for (i, z) in routing.zones.iter_mut().enumerate() {
        let mut domains = Vec::new();
        for value in std::mem::take(&mut z.domains) {
            if let Some((kind, name)) = dependency(&value) {
                if !sources.contains_key(&value) {
                    let entries = lookup(kind, name)?;
                    if entries.is_empty() {
                        return Err(err("пустой источник правил"));
                    }
                    sources.insert(value.clone(), entries);
                }
                for item in &sources[&value] {
                    let v = item.trim();
                    domain(v, false)?;
                    let lower = v.to_ascii_lowercase();
                    if ["full:", "domain:", "regexp:", "keyword:"]
                        .iter()
                        .any(|p| lower.starts_with(p))
                    {
                        return Err(err("вложенный префикс в источнике правил"));
                    }
                    count += 1;
                    size += v.len();
                    if count > 100_000 || size > FILE_LIMIT {
                        return Err(err("снимок источника превышает допустимый размер"));
                    }
                    if ipish(v) {
                        z.ips.push(v.into());
                    } else {
                        domains.push(v.into());
                    }
                }
            } else {
                domains.push(value);
            }
        }
        z.domains = domains;
        if z.tunnel_id.is_empty() {
            z.tunnel_id = state["active_id"]
                .as_str()
                .filter(|id| !z.waiting_for_connection && live.contains_key(*id))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("pending-unassigned-{}", i + 1));
        }
        for id in std::iter::once(&z.tunnel_id).chain(&z.fallback_tunnel_ids) {
            if used.insert(id.clone()) {
                connections.push(
                    identities
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| Ref::blank(id)),
                );
            }
        }
    }
    let warnings = if sources.is_empty() {
        vec![]
    } else {
        vec!["Ссылки list:/geosite:/geoip: заменены снимком содержимого. На другом роутере эти записи не обновляются вместе с исходным списком.".into()]
    };
    let doc = Document {
        format: FORMAT.into(),
        version: 1,
        routing,
        connections,
        warnings,
    };
    doc.validate()?;
    struct Limit(usize);
    impl io::Write for Limit {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len();
            if self.0 > FILE_LIMIT {
                Err(err("файл правил превышает 2 МиБ"))
            } else {
                Ok(b.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer_pretty(Limit(0), &doc).map_err(|e| err(e.to_string()))?;
    Ok(doc)
}
#[derive(Serialize)]
struct Candidate<'a> {
    id: &'a str,
    label: &'a str,
    endpoint: &'a str,
    client_iface: &'a str,
    protocol: &'a str,
    fingerprint: &'a str,
}
#[derive(Serialize)]
struct PlanRow {
    source: Ref,
    state: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    matched_tunnel_id: String,
    #[serde(serialize_with = "serialize_candidates")]
    candidates: Arc<Vec<Value>>,
    #[serde(skip_serializing_if = "str::is_empty")]
    reason: &'static str,
}
fn serialize_candidates<S: serde::Serializer>(
    v: &Arc<Vec<Value>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    v.as_slice().serialize(s)
}
#[derive(Serialize)]
pub struct Plan {
    connections: Vec<PlanRow>,
    rule_count: usize,
    waiting_rule_count: usize,
    warnings: Vec<String>,
    policy_hash: String,
}
fn plan(doc: &Document, live: &Refs, hash: String) -> Plan {
    let mut candidates: Vec<_> = live
        .values()
        .filter(|r| !r.fingerprint.is_empty())
        .collect();
    candidates.sort_by_key(|r| (&r.label, &r.id));
    let candidates = Arc::new(
        candidates
            .into_iter()
            .map(|r| {
                json!(Candidate {
                    id: &r.id,
                    label: &r.label,
                    endpoint: &r.endpoint,
                    client_iface: &r.client_iface,
                    protocol: &r.protocol,
                    fingerprint: &r.fingerprint
                })
            })
            .collect::<Vec<_>>(),
    );
    let used: HashSet<_> = doc
        .routing
        .zones
        .iter()
        .flat_map(|z| std::iter::once(&z.tunnel_id).chain(&z.fallback_tunnel_ids))
        .collect();
    let connections = doc
        .connections
        .iter()
        .filter(|r| used.contains(&r.id))
        .map(|r| {
            let mut matches = live
                .values()
                .filter(|c| !r.fingerprint.is_empty() && c.fingerprint == r.fingerprint);
            let first = matches.next();
            let (state, id) = if matches.next().is_some() {
                ("ambiguous", "")
            } else if let Some(c) = first {
                ("matched", c.id.as_str())
            } else {
                ("missing", "")
            };
            let reason = if state != "matched"
                && live
                    .get(&r.id)
                    .is_some_and(|c| r.fingerprint.is_empty() || c.fingerprint != r.fingerprint)
            {
                "identity_changed"
            } else {
                ""
            };
            PlanRow {
                source: r.clone(),
                state,
                matched_tunnel_id: id.into(),
                reason,
                candidates: candidates.clone(),
            }
        })
        .collect();
    Plan {
        connections,
        rule_count: doc.routing.zones.len(),
        waiting_rule_count: doc
            .routing
            .zones
            .iter()
            .filter(|z| z.waiting_for_connection)
            .count(),
        warnings: doc.warnings.clone(),
        policy_hash: hash,
    }
}
pub fn preview(db: &Store, raw: &RawValue) -> io::Result<Plan> {
    let doc = Document::parse(raw)?;
    let state = read(db)?;
    let live = live(&state);
    let hash = policy_hash(&current(&state)?, &refs(&state, &live)?);
    Ok(plan(&doc, &live, hash))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    document: Box<RawValue>,
    #[serde(default)]
    mappings: BTreeMap<String, String>,
    #[serde(default)]
    mapping_fingerprints: BTreeMap<String, String>,
    mode: String,
    base_routing: Option<Routing>,
    expected_policy_hash: String,
}
pub fn import(db: &Store, request: ImportRequest) -> io::Result<Value> {
    let doc = Document::parse(&request.document)?;
    let expected = &request.expected_policy_hash;
    if expected.len() != 64
        || !expected.bytes().all(|c| c.is_ascii_hexdigit())
        || !matches!(request.mode.as_str(), "append" | "replace")
        || request.mode == "replace" && request.base_routing.is_some()
    {
        return Err(err("проверьте режим импорта и ожидаемый хэш"));
    }
    if let Some(base) = &request.base_routing {
        base.validate(true)?;
    }
    let receipt = digest(&serde_json::to_vec(&request)?, 32);
    edit_document(db, move |state| {
        let live = live(state);
        let mut references = refs(state, &live)?;
        let base = current(state)?;
        let before = policy_hash(&base, &references);
        let plan = plan(&doc, &live, before.clone());
        let mut map = BTreeMap::new();
        let mut extra = Refs::new();
        for row in plan.connections {
            let src = &row.source;
            let target = match request.mappings.get(&src.id) {
                Some(id) => id.as_str(),
                None if row.state == "matched" => row.matched_tunnel_id.as_str(),
                _ => return Err(err("выберите подключение или ожидание")),
            };
            let mapped = if target.is_empty() {
                let v = src.detached(&live, &references, &extra);
                let id = v.id.clone();
                extra.insert(id.clone(), v);
                id
            } else {
                let target = live
                    .get(target)
                    .filter(|t| !t.fingerprint.is_empty())
                    .ok_or_else(|| err("выбранное подключение отсутствует"))?;
                if request
                    .mapping_fingerprints
                    .get(&src.id)
                    .unwrap_or(&src.fingerprint)
                    != &target.fingerprint
                {
                    return Err(err("отпечаток выбранного подключения изменился"));
                }
                target.id.clone()
            };
            map.insert(src.id.clone(), mapped);
        }
        if request.mappings.keys().any(|k| !map.contains_key(k))
            || request
                .mapping_fingerprints
                .keys()
                .any(|k| request.mappings.get(k).is_none_or(String::is_empty))
        {
            return Err(err("неизвестная ссылка подключения"));
        }
        let mut imported = doc.routing;
        for z in &mut imported.zones {
            z.tunnel_id = map[&z.tunnel_id].clone();
            z.waiting_for_connection = extra.contains_key(&z.tunnel_id);
            for id in &mut z.fallback_tunnel_ids {
                *id = map[id].clone();
            }
            z.normalize();
        }
        let mut candidate = if request.mode == "append" {
            let mut combined = request.base_routing.unwrap_or_else(|| base.clone());
            combined.zones.extend(imported.zones);
            combined
        } else {
            imported
        };
        if candidate.mtu == 0 {
            candidate.mtu = base.mtu;
        }
        if candidate.mode.is_empty() {
            candidate.mode = "zones".into();
        }
        candidate.validate(true)?;
        references.extend(extra);
        let after = policy_hash(&candidate, &references);
        if before != *expected {
            if before == after
                || state["routing_import_receipt"]["request"] == receipt
                    && state["routing_import_receipt"]["policy"] == before
            {
                return result(state);
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "маршрутизация изменилась; обновите предварительный просмотр",
            ));
        }
        write(state, candidate, &references)?;
        state["routing_import_receipt"] =
            json!({"request":receipt,"policy":policy_hash(&current(state)?,&references)});
        result(state)
    })
}
fn result(state: &Value) -> io::Result<Value> {
    let routing = current(state)?;
    Ok(
        json!({"routing_revision":state["routing_revision"].as_u64().unwrap_or(0),"rule_count":routing.zones.len(),"waiting_rule_count":routing.zones.iter().filter(|z|z.waiting_for_connection).count(),"routing":routing}),
    )
}
