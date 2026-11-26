//! Match a DNS question and its client address to the first applicable routing zone.
use crate::kernel::{Family, Prefix};
use crate::model::{dependency, err, hostname, ipish, Routing};
use regex_lite::Regex;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

fn literal_name(raw: &str) -> Option<&str> {
    if raw.contains(':') {
        None
    } else if raw.contains('_') {
        // Service discovery labels such as _sip._tcp are DNS names but
        // are not ordinary host names suitable for a static lookup.
        let name = raw.strip_suffix('.').unwrap_or(raw);
        hostname(name).then_some(name)
    } else {
        nfqws2_awg_profile::exact_route_hostname(raw)
    }
}

pub(crate) fn plain_rule_literal(pattern: &str, include: Option<bool>) -> Option<&str> {
    let plain = pattern.strip_prefix('.').unwrap_or(pattern);
    let plain = if include == Some(true) {
        plain.strip_prefix("*.").unwrap_or(plain)
    } else {
        plain
    };
    literal_name(plain)
}

#[derive(Default)]
struct Suffix {
    apex: bool,
    explicit_glob: bool,
}

#[derive(Default)]
pub(crate) struct Scope {
    exact: HashSet<String>,
    suffix: HashMap<String, Suffix>,
    indexed_globs: usize,
    globs: Vec<String>,
    regex: Vec<Regex>,
}
impl Scope {
    fn glob_count(&self) -> usize {
        self.indexed_globs + self.globs.len()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.globs.is_empty()
            && self.regex.is_empty()
    }
    /// Old Go or imported lists can contain a matcher unsupported by
    /// regex-lite. Other valid entries still contribute to the history view.
    pub(crate) fn add_history(&mut self, raw: &str, include: Option<bool>) -> io::Result<()> {
        let result = self.add(raw, include);
        if self.glob_count() + self.regex.len() > 256 {
            result
        } else {
            Ok(())
        }
    }
    pub(crate) fn add(&mut self, raw: &str, include: Option<bool>) -> io::Result<()> {
        let normalized = raw.trim().to_ascii_lowercase();
        let explicit_exact = normalized.starts_with("full:");
        let pattern = normalized
            .strip_prefix("domain:")
            .or_else(|| normalized.strip_prefix("full:"))
            .unwrap_or(&normalized)
            .trim();
        if let Some(plain) = plain_rule_literal(pattern, include) {
            if include == Some(false) || (include.is_none() && explicit_exact) {
                self.exact.insert(plain.to_owned());
            } else {
                self.suffix.entry(plain.to_owned()).or_default().apex = true;
            }
        } else if let Some(base) = pattern
            .strip_prefix("*.")
            .filter(|base| literal_name(base) == Some(*base))
        {
            // "*.base" matches any descendant, including several labels,
            // but its own apex only matches when another entry includes it.
            let suffix = self.suffix.entry(base.to_owned()).or_default();
            if !suffix.explicit_glob {
                suffix.explicit_glob = true;
                self.indexed_globs += 1;
            }
        } else if let Some(re) = pattern
            .strip_prefix("[re]")
            .or_else(|| pattern.strip_prefix("regexp:"))
        {
            if re.trim().is_empty() {
                return Err(err("пустое регулярное выражение DNS"));
            }
            if self
                .regex
                .iter()
                .any(|existing| existing.as_str() == re.trim())
            {
                return Ok(());
            }
            self.regex.push(
                regex_lite::RegexBuilder::new(re.trim())
                    .size_limit(64 << 10)
                    .build()
                    .map_err(|_| {
                        err("регулярное выражение DNS не поддерживается или слишком велико")
                    })?,
            );
        } else if pattern.starts_with("keyword:") || pattern.contains(['*', '#']) {
            if pattern
                .strip_prefix("keyword:")
                .is_some_and(|key| key.trim().is_empty())
            {
                return Ok(());
            }
            let glob = pattern
                .strip_prefix("keyword:")
                .map(|s| format!("*{}*", s.trim()))
                .unwrap_or_else(|| pattern.to_owned());
            if !self.globs.contains(&glob) {
                self.globs.push(glob);
            }
        } else if !ipish(pattern) {
            return Err(err("неизвестный тип шаблона DNS"));
        }
        if self.glob_count() + self.regex.len() > 256 {
            return Err(err("слишком много шаблонов DNS в правиле"));
        }
        Ok(())
    }
    pub(crate) fn match_domain(&self, name: &str) -> Option<bool> {
        if self.exact.contains(name) || self.suffix.get(name).is_some_and(|s| s.apex) {
            return Some(false);
        }
        (name
            .match_indices('.')
            .any(|(i, _)| self.suffix.contains_key(&name[i + 1..]))
            || self
                .globs
                .iter()
                .any(|g| glob(g.as_bytes(), name.as_bytes()))
            || self.regex.iter().any(|r| r.is_match(name)))
        .then_some(true)
    }
}

// Anchored, ASCII DNS names. Remember the most recent '*' and retry the
// following literal suffix one character later; no recursion or allocations.
fn glob(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star = None;
    let mut retry = 0;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                p += 1;
                star = Some(p);
                retry = n;
            }
            Some(c) if *c == b'#' || *c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some(tail) => {
                    retry += 1;
                    n = retry;
                    p = tail;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|c| *c == b'*')
}

struct Rule {
    zone: usize,
    sources: Vec<Prefix>,
    domains: Scope,
    catch_all: bool,
    history_key: Option<String>,
    tunnel: bool,
    legacy_member: bool,
}
impl Rule {
    fn matches_source(&self, client: Option<IpAddr>) -> bool {
        self.sources.is_empty()
            || client.is_some_and(|ip| self.sources.iter().any(|s| s.contains(ip)))
    }
}
pub struct Policy {
    rules: Vec<Rule>,
    legacy_full: bool,
    legacy_ingress: Vec<(Prefix, Option<String>)>,
}

fn normalized_name(name: &str) -> Option<Cow<'_, str>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if !hostname(name) {
        return None;
    }
    Some(if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    })
}

/// A source-bound domain needs this client's actual CDN answer. A legacy
/// global plain name in Resolve mode only seeds the periodic apex snapshot.
pub fn dynamic(r: &Routing) -> bool {
    let ordered_default = r
        .zones
        .iter()
        .any(|z| z.enabled && !z.waiting_for_connection && z.only_catch_all());
    r.mode != "off"
        && r.global_default_zone().is_none()
        && r.zones
            .iter()
            .filter(|z| z.enabled && !z.waiting_for_connection)
            .any(|z| {
                z.domains.iter().any(|entry| {
                    let pattern = entry.to_ascii_lowercase();
                    let plain = pattern
                        .strip_prefix("domain:")
                        .or_else(|| pattern.strip_prefix("full:"))
                        .unwrap_or(&pattern)
                        .trim();
                    !ipish(entry)
                        && !crate::model::catch_all(entry)
                        && (ordered_default
                            || r.domain_source == "dnsproxy"
                            || !z.source_ips.is_empty()
                            || pattern.contains(['*', '#'])
                            || ["regexp:", "[re]", "keyword:", "list:", "geosite:"]
                                .iter()
                                .any(|p| pattern.starts_with(p))
                            || plain
                                .strip_prefix('.')
                                .is_some_and(|p| literal_name(p).is_some())
                            || (z.include_subdomains == Some(true)
                                && literal_name(plain).is_some()))
                })
            })
}

impl Policy {
    pub fn compile(config: &Routing) -> io::Result<Self> {
        if !dynamic(config) {
            return Ok(Self {
                rules: Vec::new(),
                legacy_full: false,
                legacy_ingress: Vec::new(),
            });
        }
        Self::compile_rules(config, false)
    }

    /// The old watchdog evaluates the original selected profile's zone
    /// order. A source-only IP rule is also a name decision for that client,
    /// although it has no DNS set to populate.
    pub fn compile_legacy_full(config: &Routing) -> io::Result<Self> {
        Self::compile_rules(config, true)
    }

    fn compile_rules(config: &Routing, legacy_full: bool) -> io::Result<Self> {
        let mut rules = Vec::new();
        let mut bytes = 0usize;
        let (mut globs, mut regex) = (0, 0);
        let mut global_finished = false;
        for (zone, z) in config
            .zones
            .iter()
            .enumerate()
            .filter(|(_, z)| z.enabled && !z.waiting_for_connection)
        {
            let global = z.source_ips.is_empty();
            let explicit_catch = z.domains.iter().any(|s| s.trim() == "*")
                || z.ips
                    .iter()
                    .any(|s| matches!(s.trim(), "0.0.0.0/0" | "::/0"));
            let mut catch_all = if legacy_full {
                explicit_catch
            } else {
                z.dns_catch_all()
            };
            if legacy_full && global && global_finished {
                continue;
            }
            global_finished |= legacy_full && global && catch_all;
            if z.domains.is_empty() && !catch_all && (!legacy_full || global) {
                continue;
            }
            let mut domains = Scope::default();
            for entry in &z.domains {
                bytes += entry.len();
                if bytes > 2 << 20 {
                    return Err(err("шаблоны DNS превышают 2 МиБ"));
                }
                if dependency(entry).is_some() {
                    return Err(err(
                        "требуется снимок списка или Geo перед применением DNS-масок",
                    ));
                }
                if entry != "*" && (!legacy_full || !crate::model::catch_all(entry)) {
                    domains.add(entry, z.include_subdomains)?;
                    if globs + domains.glob_count() > 256 || regex + domains.regex.len() > 32 {
                        return Err(err(
                            "допускается до 256 масок и 32 регулярных выражений DNS",
                        ));
                    }
                }
            }
            globs += domains.glob_count();
            regex += domains.regex.len();
            let legacy_member = legacy_full && !global && (explicit_catch || !domains.is_empty());
            catch_all |= legacy_full && !global && domains.is_empty();
            rules.push(Rule {
                zone,
                history_key: if catch_all {
                    None
                } else {
                    Some(crate::discoveries::rule_key(z)?)
                },
                sources: z
                    .source_ips
                    .iter()
                    .map(|s| s.parse())
                    .collect::<io::Result<_>>()?,
                domains,
                catch_all,
                tunnel: z.direction() == "tunnel",
                legacy_member,
            });
        }
        Ok(Self {
            rules,
            legacy_full,
            legacy_ingress: Vec::new(),
        })
    }

    pub(crate) fn with_legacy_ingress(mut self, ingress: Vec<(Prefix, Option<String>)>) -> Self {
        self.legacy_ingress = ingress;
        self
    }

    pub(crate) fn legacy_accepts_peer(&self, client: IpAddr, ingress: Option<&str>) -> bool {
        let client = client.to_canonical();
        self.legacy_ingress
            .iter()
            .filter(|(sources, _)| sources.contains(client))
            .all(|(_, bridge)| {
                bridge
                    .as_deref()
                    .zip(ingress)
                    .is_some_and(|(pinned, actual)| pinned == actual)
            })
    }
    fn rule_for_zone(&self, zone: usize) -> Option<&Rule> {
        let index = self
            .rules
            .binary_search_by_key(&zone, |rule| rule.zone)
            .ok()?;
        self.rules.get(index)
    }
    pub fn history_key(&self, zone: usize) -> Option<&str> {
        self.rule_for_zone(zone)?.history_key.as_deref()
    }
    pub fn matches_single_client(&self, zone: usize, client: IpAddr) -> bool {
        let client = client.to_canonical();
        client.is_ipv4()
            && self
                .rule_for_zone(zone)
                .is_some_and(|rule| rule.sources.as_slice() == [Prefix::host(client)])
    }
    pub fn mixed_firmware_sources(&self) -> bool {
        let [first, second] = self.rules.as_slice() else {
            return false;
        };
        let client = |rule: &Rule| match rule.sources.as_slice() {
            [source] => {
                *source == Prefix::host(source.sample())
                    && source.family() == Family::V4
                    && source.safe()
            }
            _ => false,
        };
        !self.legacy_full
            && first.tunnel
            && second.tunnel
            && !first.catch_all
            && !second.catch_all
            && (first.sources.is_empty() && client(second)
                || second.sources.is_empty() && client(first))
    }
    pub fn history_match(&self, zone: usize, name: &str) -> Option<(&str, bool)> {
        let rule = self.rule_for_zone(zone)?;
        Some((
            rule.history_key.as_deref()?,
            rule.domains.match_domain(name)?,
        ))
    }
    pub fn trace_decision(&self, zone: usize, address: Option<IpAddr>) -> Option<&'static str> {
        let rule = self.rule_for_zone(zone)?;
        Some(if rule.tunnel {
            "tunnel"
        } else if rule.sources.is_empty()
            && (!rule.catch_all || self.legacy_full)
            && address.is_some_and(crate::kernel::shared_cdn_address)
        {
            "cdn-skip"
        } else {
            "direct"
        })
    }
    pub fn trace_default(&self) -> &'static str {
        if self.legacy_full {
            "tunnel"
        } else {
            "direct"
        }
    }

    pub fn uses_legacy_full(&self) -> bool {
        self.legacy_full
    }

    /// History offers names only. Each rule uses its own configured source
    /// network when the compiler converts these candidates into selectors.
    pub fn archive_zones<'a>(
        &'a self,
        name: &'a str,
        qtype: u16,
    ) -> impl Iterator<Item = usize> + 'a {
        let name = normalized_name(name);
        let family = match qtype {
            1 => Some(Family::V4),
            28 => Some(Family::V6),
            _ => None,
        };
        self.rules
            .iter()
            .filter(move |rule| {
                !self.legacy_full
                    && !rule.catch_all
                    && family.is_some_and(|family| {
                        rule.sources.is_empty()
                            || rule.sources.iter().any(|source| source.family() == family)
                    })
                    && name
                        .as_ref()
                        .is_some_and(|name| rule.domains.match_domain(name).is_some())
            })
            .map(|rule| rule.zone)
    }

    /// The name classifier's source-bound destination sets, in the original
    /// profile order. The selected first-match trace rule can be global.
    pub fn legacy_dns_zones(&self, name: &str, client: Option<IpAddr>) -> Vec<usize> {
        let Some(name) = normalized_name(name) else {
            return Vec::new();
        };
        let client = client.map(|ip| ip.to_canonical());
        self.rules
            .iter()
            .filter(|rule| {
                rule.legacy_member
                    && rule.matches_source(client)
                    && (rule.catch_all || rule.domains.match_domain(&name).is_some())
            })
            .map(|rule| rule.zone)
            .collect()
    }

    pub fn matched(&self, name: &str, client: Option<IpAddr>) -> Option<usize> {
        let name = normalized_name(name)?;
        let client = client.map(|ip| ip.to_canonical());
        self.rules
            .iter()
            .find(|r| {
                r.matches_source(client) && (r.catch_all || r.domains.match_domain(&name).is_some())
            })
            .map(|r| r.zone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_full_name_decisions_keep_original_order_but_learn_all_matching_client_sets() {
        let routing: Routing = serde_json::from_value(json!({
            "mode":"full", "domain_source":"resolve",
            "zones":[
                {"enabled":true,"route":"direct","ips":["192.0.2.8"],"source_ips":["192.168.1.9"]},
                {"enabled":true,"route":"tunnel","domains":["office.test","*"]},
                {"enabled":true,"route":"direct","domains":["*.office.test"],"source_ips":["192.168.1.0/24"]},
                {"enabled":true,"route":"direct","domains":["office.test"]},
                {"enabled":true,"route":"tunnel","domains":["work.office.test"],"source_ips":["192.168.1.9"]},
                {"enabled":true,"route":"tunnel","domains":["work.office.test"],"source_ips":["192.168.2.0/24"]}
            ]
        })).unwrap();
        let scope = Policy::compile_legacy_full(&routing).unwrap();
        let client = Some("::ffff:192.168.1.9".parse().unwrap());
        assert_eq!(scope.matched("work.office.test", client), Some(0));
        assert_eq!(scope.matched("office.test", None), Some(1));
        assert_eq!(
            scope.matched("other.test", Some("192.168.1.7".parse().unwrap())),
            Some(1)
        );
        assert_eq!(scope.legacy_dns_zones("WORK.OFFICE.TEST.", client), [2, 4]);
        assert!(scope.legacy_dns_zones("work.office.test", None).is_empty());
        assert_eq!(scope.trace_default(), "tunnel");
        assert_eq!(Policy::compile(&routing).unwrap().trace_default(), "direct");
    }

    #[test]
    fn legacy_full_marker_matches_only_its_apex_until_subdomains_are_explicitly_enabled() {
        let mut r: Routing = serde_json::from_value(json!({
            "mode":"zones", "domain_source":"dnsproxy",
            "zones":[{"enabled":true,"domains":["full:office.example", "*.other.example"]}]
        }))
        .unwrap();
        for include in [None, Some(false), Some(true)] {
            r.zones[0].include_subdomains = include;
            let compiled = Policy::compile(&r).unwrap();
            let subdomains = (include == Some(true)).then_some(0);
            assert_eq!(compiled.matched("office.example", None), Some(0));
            assert_eq!(compiled.matched("child.office.example", None), subdomains);
            assert_eq!(compiled.matched("other.example", None), subdomains);
            assert_eq!(compiled.matched("child.other.example", None), Some(0));
        }
    }
    #[test]
    fn go_masks_subdomain_switch_and_first_matching_client_rule() {
        let r:Routing=serde_json::from_value(json!({"mode":"zones","domain_source":"resolve","zones":[
            {"name":"disabled","enabled":false,"domains":["*"]},
            {"enabled":true,"source_ips":["2001:db8:4::/64","192.0.2.3"],"domains":["full:Office.Test","e##.test","*media*.test"],"include_subdomains":false},
            {"enabled":true,"domains":["*.Office.Test"],"include_subdomains":true},
            {"enabled":true,"domains":["[re]^node[0-9]+[.]test$","keyword:ads",".site.test"]},
            {"enabled":true,"domains":["*"],"source_ips":["10.0.0.0/8"]}
        ]})).unwrap();
        let p = Policy::compile(&r).unwrap();
        let v4 = Some("::ffff:192.0.2.3".parse().unwrap());
        let v6 = Some("2001:db8:4::18".parse().unwrap());
        assert_eq!(p.matched("OFFICE.TEST.", v6), Some(1));
        assert_eq!(p.matched("office.test", None), Some(2));
        assert_eq!(p.matched("child.office.test", v4), Some(2));
        assert_eq!(p.matched("e12.test", v4), Some(1));
        assert_eq!(p.matched("e123.test", v4), None);
        assert_eq!(p.matched("sub.media.test", v4), Some(1));
        for name in ["node12.test", "ads.internal", "x.site.test"] {
            assert_eq!(p.matched(name, None), Some(3));
        }
        assert_eq!(p.matched("othersite.test", None), None);
        assert_eq!(
            p.matched("elsewhere.test", Some("10.5.9.1".parse().unwrap())),
            Some(4)
        );
    }
    #[test]
    fn only_active_dynamic_domains_enable_observation_and_limits_fail_at_compile() {
        let mut r: Routing =
            serde_json::from_value(json!({"mode":"zones","domain_source":"resolve","zones":[
                {"enabled":true,"domains":["full:host.test"],"include_subdomains":false}
            ]}))
            .unwrap();
        assert!(!dynamic(&r));
        r.zones[0].include_subdomains = None;
        assert!(!dynamic(&r));
        r.zones[0].source_ips.push("192.0.2.1".into());
        r.zones[0].include_subdomains = Some(false);
        assert!(dynamic(&r));
        let source_policy = Policy::compile(&r).unwrap();
        assert_eq!(
            source_policy.matched("host.test", Some("192.0.2.1".parse().unwrap())),
            Some(0)
        );
        assert_eq!(source_policy.matched("host.test", None), None);
        r.zones[0].source_ips.clear();
        for name in [".svc.test", "domain:_sip._tcp.test."] {
            r.zones[0].include_subdomains = Some(true);
            r.zones[0].domains = vec![name.into()];
            crate::model::domain(name, true).unwrap();
            assert!(dynamic(&r));
            let policy = Policy::compile(&r).unwrap();
            let apex = name
                .strip_prefix('.')
                .or_else(|| name.strip_prefix("domain:"))
                .unwrap();
            assert_eq!(policy.matched(apex, None), Some(0));
            assert_eq!(policy.matched(&format!("one.{apex}"), None), Some(0));
        }
        r.zones[0].include_subdomains = Some(false);
        for bad in ["127.1", "0x7f000001", "bad.test.."] {
            r.zones[0].domains = vec![bad.into()];
            assert!(!dynamic(&r));
            r.domain_source = "dnsproxy".into();
            assert!(Policy::compile(&r).is_err());
            r.domain_source = "resolve".into();
        }
        r.zones[0].domains = vec!["full:host.test".into()];
        r.domain_source = "dnsproxy".into();
        assert!(dynamic(&r));
        r.zones[0].waiting_for_connection = true;
        assert!(!dynamic(&r));
        r.zones[0].waiting_for_connection = false;
        r.zones[0].domains = vec!["list:unexpanded".into()];
        assert!(Policy::compile(&r).is_err());
        r.zones[0].domains = (0..33).map(|n| format!("[re]^foo{n}$")).collect();
        assert!(Policy::compile(&r).is_err());
    }
    #[test]
    fn anchored_star_and_hash_match_without_regex_allocations() {
        for (p, n, expected) in [
            ("*", "abc", true),
            ("**a*bc", "bababc", true),
            ("*a*bc", "bababcx", false),
            ("*ip*", "domain.test", false),
            ("srv#.test", "srv1.test", true),
            ("srv#.test", "srv.test", false),
            ("*.test", "test", false),
            ("*.test", "one.two.test", true),
            ("????", "test", false),
        ] {
            assert_eq!(glob(p.as_bytes(), n.as_bytes()), expected, "{p} versus {n}");
        }
    }
    #[test]
    fn indexed_subdomain_globs_preserve_exact_and_additional_results_and_share_the_limit() {
        for include in [None, Some(false)] {
            let mut scope = Scope::default();
            scope.add("*.example.test", include).unwrap();
            scope.add("*.example.test", include).unwrap();
            assert_eq!(scope.glob_count(), 1);
            for (name, expected) in [
                ("example.test", None),
                ("new.example.test", Some(true)),
                ("a.b.example.test", Some(true)),
                ("notexample.test", None),
            ] {
                assert_eq!(scope.match_domain(name), expected);
            }
            scope.add("example.test", include).unwrap();
            scope.add("a.b.example.test", include).unwrap();
            assert_eq!(scope.match_domain("example.test"), Some(false));
            assert_eq!(scope.match_domain("a.b.example.test"), Some(false));
            assert_eq!(scope.match_domain("new.example.test"), Some(true));
            let mut reversed = Scope::default();
            reversed.add("example.test", include).unwrap();
            reversed.add("*.example.test", include).unwrap();
            assert_eq!(reversed.glob_count(), 1);
            assert_eq!(reversed.match_domain("example.test"), Some(false));
        }
        let mut scope = Scope::default();
        scope.add("*.a#*.test", Some(false)).unwrap();
        scope.add("*.literal.test.", Some(false)).unwrap();
        assert_eq!(scope.indexed_globs, 0);
        assert_eq!(scope.globs.len(), 2);
        assert_eq!(scope.match_domain("foo.a1b.test"), Some(true));
        let mut r: Routing = serde_json::from_value(json!({"mode":"zones","zones":[
            {"enabled":true,"domains":["word*.test"]},{"enabled":true,"domains":[]}
        ]}))
        .unwrap();
        r.zones[1].domains = (0..255).map(|n| format!("*.s{n}.test")).collect();
        assert!(Policy::compile(&r).is_ok());
        r.zones[1].domains.push("*.extra.test".into());
        assert!(Policy::compile(&r).is_err());
    }
}
