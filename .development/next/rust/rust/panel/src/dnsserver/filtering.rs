use super::catalog::{Feed, Index, Status, Verdict};
use super::config::{domain, invalid};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
};

const ADGUARD: &str = "adguard-dns";
const NETSEER: &str = "-netseer-ipaddr-assoc";
fn netseer(name: &str) -> bool {
    matches!(
        name,
        "*-netseer-ipaddr-assoc.xy.fbcdn.net" | "*-netseer-ipaddr-assoc.xz.fbcdn.net"
    )
}
pub fn normalize(v: &mut Value) -> io::Result<()> {
    let mut lists = Vec::new();
    for id in v["lists"]
        .as_array()
        .ok_or_else(|| invalid("неверные списки DNS"))?
    {
        match id.as_str().unwrap_or("").trim() {
            ADGUARD | "hagezi-light" | "hagezi-normal" | "hagezi-pro" | "oisd-small"
            | "blocklist-ads" | "blocklist-tracking" => {
                if lists.is_empty() {
                    lists.push(ADGUARD);
                }
            }
            _ => return Err(invalid("неизвестный список DNS-блокировки")),
        }
    }
    v["lists"] = json!(lists);
    for r in v["custom_rules"]
        .as_array_mut()
        .ok_or_else(|| invalid("ожидались правила DNS"))?
    {
        let name = r["domain"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let name = if netseer(&name) {
            name
        } else if let Some(suffix) = name.strip_prefix("*.") {
            format!("*.{}", domain(suffix)?)
        } else {
            domain(&name)?
        };
        let cat = match r
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
        {
            "" | "trackers" => "trackers",
            "mixed" => "mixed",
            "ads" => "ads",
            _ => return Err(invalid("категория должна быть ads, trackers или mixed")),
        };
        *r = json!({"domain":name,"category":cat});
    }
    let mut seen = HashSet::new();
    let mut allow = Vec::new();
    for raw in v["allowlist"]
        .as_array()
        .ok_or_else(|| invalid("ожидался список исключений"))?
    {
        let raw = raw.as_str().unwrap_or("").trim();
        let n = domain(raw.strip_prefix("*.").unwrap_or(raw))?;
        if seen.insert(n.clone()) {
            allow.push(n);
        }
    }
    v["allowlist"] = json!(allow);
    Ok(())
}
#[derive(Default)]
pub struct Filter {
    pub(super) feed: Option<Arc<Feed>>,
    domains: HashMap<String, String>,
    children: HashMap<String, String>,
    netseer: HashMap<String, String>,
    allow: HashSet<String>,
}
pub struct Hit {
    pub domain: String,
    pub rule: String,
    pub category: String,
    pub source: &'static str,
}
impl Hit {
    pub fn annotate(&self, v: &mut Value) {
        v["block_domain"] = json!(self.domain);
        v["block_category"] = json!(self.category);
        v["block_rule"] = json!(self.rule);
        v["block_source"] = json!(self.source);
    }
}
impl Filter {
    pub fn compile(v: &Value) -> Option<Self> {
        if v["enabled"] != true {
            return None;
        }
        let mut f = Self {
            feed: v["lists"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
                .then(|| Arc::new(Feed::default())),
            ..Default::default()
        };
        for r in v["custom_rules"].as_array().into_iter().flatten() {
            let name = r["domain"].as_str().expect("validated rule");
            let cat = r["category"].as_str().expect("validated category");
            let (map, key) = if netseer(name) {
                (&mut f.netseer, name.split_once('.').unwrap().1)
            } else if let Some(s) = name.strip_prefix("*.") {
                (&mut f.children, s)
            } else {
                (&mut f.domains, name)
            };
            if name.starts_with('*') {
                map.insert(key.to_owned(), cat.to_owned());
                continue;
            }
            map.entry(key.to_owned())
                .and_modify(|v| {
                    if v != cat {
                        *v = "mixed".into();
                    }
                })
                .or_insert_with(|| cat.to_owned());
        }
        f.allow.extend(
            v["allowlist"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
        Some(f)
    }
    pub fn allowed(&self, name: &str) -> bool {
        suffixes(name).any(|s| self.allow.contains(s))
    }
    fn custom(&self, name: &str) -> Option<Hit> {
        let create = |rule: String, cat: &str| Hit {
            domain: name.into(),
            rule,
            category: cat.into(),
            source: "custom",
        };
        let mut best = None;
        for suffix in suffixes(name) {
            if let Some(cat) = self.domains.get(suffix) {
                best = Some(create(suffix.into(), cat));
                break;
            }
            if suffix != name {
                if let Some(cat) = self.children.get(suffix) {
                    best = Some(create(format!("*.{suffix}"), cat));
                    break;
                }
            }
        }
        if let Some((label, parent)) = name.split_once('.') {
            if best.as_ref().is_none_or(|h| h.rule != name)
                && label.len() > NETSEER.len()
                && label.ends_with(NETSEER)
            {
                if let Some(cat) = self.netseer.get(parent) {
                    return Some(create(format!("*{NETSEER}.{parent}"), cat));
                }
            }
        }
        best
    }
    pub fn evaluate(&self, name: &str, kind: u16, source: Option<&Index>) -> (Option<Hit>, bool) {
        if self.allowed(name) {
            return (None, true);
        }
        if let Some(hit) = self.custom(name) {
            return (Some(hit), false);
        }
        match source.and_then(|s| s.lookup(name, kind)) {
            None => (None, false),
            Some(Verdict::Allow) => (None, true),
            Some(Verdict::Block(rule)) => (
                Some(Hit {
                    domain: name.into(),
                    rule,
                    category: "mixed".into(),
                    source: ADGUARD,
                }),
                false,
            ),
        }
    }
    #[cfg(test)]
    fn hit(&self, name: &str) -> Option<Hit> {
        self.evaluate(name, 1, None).0
    }
    pub fn response_hit(
        &self,
        domain: &str,
        kind: u16,
        answer: &[u8],
        initial: Option<&Index>,
        previously_allowed: bool,
    ) -> io::Result<Option<Hit>> {
        let current = self.feed.as_ref().and_then(|feed| feed.snapshot());
        let source = current.as_deref();
        let same = match (initial, source) {
            (Some(before), Some(now)) => std::ptr::eq(before, now),
            (None, None) => true,
            _ => false,
        };
        let (hit, allowed) = if same {
            (None, previously_allowed)
        } else {
            self.evaluate(domain, kind, source)
        };
        if hit.is_some() || allowed {
            return Ok(hit);
        }
        nfqws2_dns::visit_typed_filter_targets(answer, |name, record_type| {
            self.evaluate(name, record_type, source).0
        })
    }
    fn count(&self) -> usize {
        self.domains.len() + self.children.len() + self.netseer.len()
    }
}
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |s| s.split_once('.').map(|(_, suffix)| suffix))
}
pub fn status(v: &Value, active: Option<&Filter>, saved: Option<&Status>) -> Value {
    let enabled = v["enabled"] == true;
    let catalog = v["lists"].as_array().is_some_and(|a| !a.is_empty());
    let active_status = active.and_then(|f| f.feed.as_ref()).map(|f| f.status());
    let empty = Status::default();
    let current = active_status.as_ref().unwrap_or(&empty);
    let list = active_status.as_ref().or(saved).unwrap_or(&empty);
    let count = active.map_or(0, Filter::count) + current.rules;
    json!({"enabled":enabled,"ready":enabled && count>0 && (!catalog||current.rules>0),"rules":count,"updating":current.updating,"last_error":current.error,"last_updated":if catalog{&list.updated}else{""},"ignored_rules":current.ignored,"approximate":current.rules>0,
        "lists":[{"id":ADGUARD,"name":"AdGuard DNS filter","category":"mixed","url":"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt","homepage":"https://github.com/AdguardTeam/AdGuardSDNSFilter","description":"Официальный DNS-фильтр AdGuard. Поддерживаются доменные правила и исключения, списки типов DNS-записей с исключениями и шаблоны со звёздочкой в первой части имени.","selected":catalog,"rules":list.rules,"last_error":list.error,"last_updated":list.updated}]})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_custom_rules_exceptions_and_bounded_patterns_match_go() {
        let mut cfg = json!({"enabled":true,"lists":["hagezi-pro","adguard-dns"],"allowlist":["*.allow.example","ALLOW.EXAMPLE"],"custom_rules":[
            {"domain":"example","category":"ads"},{"domain":"Example.","category":"trackers"},
            {"domain":"*.only.test","category":"trackers"},{"domain":"*-netseer-ipaddr-assoc.xy.fbcdn.net","category":"trackers"}]});
        normalize(&mut cfg).unwrap();
        assert_eq!(cfg["lists"], json!(["adguard-dns"]));
        assert_eq!(cfg["allowlist"], json!(["allow.example"]));
        let f = Filter::compile(&cfg).unwrap();
        assert!(f.hit("x.allow.example").is_none());
        assert_eq!(f.hit("a.example").unwrap().category, "mixed");
        assert!(f.hit("only.test").is_none());
        assert_eq!(f.hit("a.only.test").unwrap().rule, "*.only.test");
        assert!(f.hit("z-netseer-ipaddr-assoc.xy.fbcdn.net").is_some());
        assert!(f.hit("x.z-netseer-ipaddr-assoc.xy.fbcdn.net").is_none());
        cfg["custom_rules"][0]["domain"] = json!("x*invalid");
        assert!(normalize(&mut cfg).is_err());
    }
}
