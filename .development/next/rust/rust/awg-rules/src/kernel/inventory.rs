use super::{
    err,
    plan::{Backend, Family, Plan, Prefix, Selector},
};
use nfqws2_router_command::Runner;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    time::Instant,
};

const TABLE: &str = "17842";
const SCOPED_BASE: u16 = 17843;
pub(super) const PROBE_IP: &str = "2606:4700:4700::1111";
const PROBE_TABLE: u16 = 17907;
pub(super) const PREF: &str = "68";
const STOP_PREF: &str = "69";
pub(super) const PROTO: &str = "242";
pub(super) const TAG: &str = "n2s-awg-cidr";

pub(super) fn valid_zone(firewall: Backend, name: &str) -> bool {
    match firewall {
        Backend::Legacy => false,
        Backend::Fw4 => super::fw4::valid_zone(name),
        Backend::Fw3 => {
            (1..=11).contains(&name.len())
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        }
    }
}

pub(super) fn fw3_forward_chain(zone: Option<&str>) -> String {
    format!("zone_{}_forward", zone.unwrap_or("lan"))
}
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub(super) enum Firewall {
    Nat,
    Out,
    In,
    Clamp,
    MssIn(u16),
    MssOut(u16),
}
impl Firewall {
    fn location(self) -> (&'static str, &'static str) {
        match self {
            Self::Nat => ("nat", "POSTROUTING"),
            Self::Out | Self::In => ("filter", "FORWARD"),
            Self::Clamp | Self::MssIn(_) | Self::MssOut(_) => ("mangle", "FORWARD"),
        }
    }
    fn spec(self, iface: &str, selector: Selector, in_lan_chain: bool) -> Vec<String> {
        let dest = selector.dest.to_string();
        let src = selector.source.to_string();
        let mut args = match self {
            Self::Nat => vec!["-o", iface],
            Self::Out if in_lan_chain => vec!["-o", iface],
            Self::Out => vec!["-i", "br+", "-o", iface],
            Self::In => vec![
                "-i",
                iface,
                "-o",
                "br+",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
            ],
            Self::Clamp | Self::MssIn(_) | Self::MssOut(_) => vec![
                if matches!(self, Self::MssIn(_)) {
                    "-i"
                } else {
                    "-o"
                },
                iface,
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
            ],
        };
        let (source, destination) = if self == Self::In {
            (
                (!selector.dest.any()).then_some(dest.as_str()),
                (!selector.source.any()).then_some(src.as_str()),
            )
        } else {
            (
                (!selector.source.any()).then_some(src.as_str()),
                (!selector.dest.any()).then_some(dest.as_str()),
            )
        };
        let mut addr = Vec::with_capacity(4);
        if let Some(s) = source {
            addr.extend(["-s", s]);
        }
        if let Some(d) = destination {
            addr.extend(["-d", d]);
        }
        args.splice(..0, addr);
        args.extend(["-m", "comment", "--comment", TAG, "-j"]);
        args.extend(match self {
            Self::Nat => vec!["MASQUERADE"],
            Self::Out | Self::In => vec!["ACCEPT"],
            Self::Clamp => vec!["TCPMSS", "--clamp-mss-to-pmtu"],
            Self::MssIn(_) | Self::MssOut(_) => vec!["TCPMSS", "--set-mss"],
        });
        let mut args: Vec<_> = args.into_iter().map(str::to_owned).collect();
        if let Self::MssIn(n) | Self::MssOut(n) = self {
            args.push(n.to_string());
        }
        args
    }
    pub(super) fn legacy_rules(plan: &Plan) -> &'static [Self] {
        if plan.mss.is_empty() {
            &[Self::Nat, Self::Out, Self::In, Self::Clamp]
        } else {
            &[Self::Nat, Self::Out, Self::In]
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Object {
    Firewall(Selector, String, Firewall),
    Fw3Forward(Selector, String, String),
    Set(Family, String),
    SetMember(Prefix, std::sync::Arc<str>),
    SetFirewall(Family, String, Firewall),
    GroupFirewall(Family, String, String, Option<String>, Firewall),
    Classifier(Family, Vec<super::marked::Group>),
    MarkLookup(Family, u8),
    MarkFence(Family, u8),
    Native(Selector, String, super::fw4::Rule),
    Route(Prefix, String, u16),
    Rule(Family),
    PackedLookup(Family),
    ProbeLookup(String),
    FullGuard(super::full::Guard),
    LegacyV6Reject(String),
    LegacyClassifier(Family, Vec<super::legacy_scope::Rule>),
    LegacyLookup(Family, bool),
    Scoped(Selector, u16, bool),
    /// Independent terminal RPDB rule. It survives removal of the TUN device.
    Stop(Selector, bool),
    Redirect(Family, String, &'static str),
}
impl Object {
    pub(super) fn fixed_mss(&self) -> bool {
        matches!(
            self,
            Self::Firewall(_, _, Firewall::MssIn(_) | Firewall::MssOut(_))
        )
    }
    pub(super) fn mss_rule(&self) -> bool {
        self.fixed_mss()
            || matches!(
                self,
                Self::Firewall(_, _, Firewall::Clamp)
                    | Self::SetFirewall(_, _, Firewall::Clamp)
                    | Self::GroupFirewall(_, _, _, _, Firewall::Clamp)
            )
    }
    pub(super) fn xtables(&self) -> Option<(&'static str, &str, Vec<String>)> {
        match self {
            Self::Firewall(n, iface, fw) => {
                let (table, chain) = fw.location();
                Some((table, chain, fw.spec(iface, *n, false)))
            }
            Self::Fw3Forward(n, iface, chain) => {
                Some(("filter", chain, Firewall::Out.spec(iface, *n, true)))
            }
            Self::LegacyV6Reject(wan) => Some((
                "filter",
                "FORWARD",
                [
                    "-o",
                    wan,
                    "-m",
                    "comment",
                    "--comment",
                    TAG,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp6-adm-prohibited",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            )),
            Self::SetFirewall(family, iface, fw) | Self::GroupFirewall(family, iface, _, _, fw) => {
                let any = family.any();
                let mut spec = fw.spec(
                    iface,
                    Selector {
                        source: any,
                        dest: any,
                    },
                    false,
                );
                let comment = spec.windows(2).position(|v| v == ["-m", "comment"])?;
                let direction = if *fw == Firewall::In { "src" } else { "dst" };
                spec.splice(
                    comment..comment,
                    [
                        "-m".into(),
                        "set".into(),
                        "--match-set".into(),
                        super::packed::name(
                            *family,
                            match self {
                                Self::GroupFirewall(_, _, token, _, _) => token,
                                _ => iface,
                            },
                        ),
                        direction.into(),
                    ],
                );
                if let Self::GroupFirewall(_, _, _, Some(source), _) = self {
                    let direction = if *fw == Firewall::In { "dst" } else { "src" };
                    spec.splice(
                        comment..comment,
                        [
                            "-m".into(),
                            "set".into(),
                            "--match-set".into(),
                            super::packed::name(*family, source),
                            direction.into(),
                        ],
                    );
                }
                let (table, chain) = fw.location();
                Some((table, chain, spec))
            }
            Self::Redirect(_, bridge, proto) => Some((
                "nat",
                "PREROUTING",
                [
                    "-i",
                    bridge,
                    "-p",
                    proto,
                    "-m",
                    proto,
                    "--dport",
                    "53",
                    "-m",
                    "comment",
                    "--comment",
                    TAG,
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    "5354",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            )),
            _ => None,
        }
    }
    pub(super) fn family(&self) -> Family {
        match self {
            Self::FullGuard(guard) => guard.family(),
            Self::LegacyV6Reject(_) | Self::ProbeLookup(_) => Family::V6,
            Self::Rule(f)
            | Self::PackedLookup(f)
            | Self::MarkLookup(f, _)
            | Self::MarkFence(f, _)
            | Self::Classifier(f, _)
            | Self::LegacyClassifier(f, _)
            | Self::LegacyLookup(f, _)
            | Self::GroupFirewall(f, ..)
            | Self::Redirect(f, ..)
            | Self::Set(f, _)
            | Self::SetFirewall(f, ..) => *f,
            Self::SetMember(p, _) => p.family(),
            Self::Native(s, ..)
            | Self::Firewall(s, ..)
            | Self::Fw3Forward(s, ..)
            | Self::Scoped(s, ..)
            | Self::Stop(s, _) => s.dest.family(),
            Self::Route(p, ..) => p.family(),
        }
    }
    pub fn is_rule(&self) -> bool {
        matches!(
            self,
            Self::Rule(_)
                | Self::PackedLookup(_)
                | Self::MarkLookup(..)
                | Self::ProbeLookup(_)
                | Self::LegacyLookup(..)
                | Self::Scoped(..)
                | Self::FullGuard(super::full::Guard::SourceLookup(_))
        )
    }
    pub fn table(&self) -> Option<u16> {
        match self {
            Self::LegacyLookup(..)
            | Self::Rule(_)
            | Self::PackedLookup(_)
            | Self::FullGuard(super::full::Guard::SourceLookup(_)) => Some(17842),
            Self::Scoped(_, t, _) | Self::Route(_, _, t) => Some(*t),
            Self::ProbeLookup(_) => Some(PROBE_TABLE),
            Self::MarkLookup(_, s) | Self::MarkFence(_, s) => Some(super::marked::table(*s)),
            _ => None,
        }
    }
    pub fn is_stop(&self) -> bool {
        matches!(
            self,
            Self::LegacyV6Reject(_) | Self::Stop(..) | Self::MarkFence(..) | Self::FullGuard(_)
        ) && !self.is_rule()
    }
}
pub(super) fn objects(plan: &Plan) -> BTreeSet<Object> {
    if plan.empty() {
        return BTreeSet::new();
    }
    let mut out = BTreeSet::new();
    if plan.ordered_default && plan.flows().next().is_some() {
        out.insert(Object::FullGuard(super::full::Guard::Main(Family::V4)));
    }
    if let Some(endpoints) = &plan.full_endpoints {
        super::full::objects(plan, endpoints, &mut out);
    }
    if let Some(wan) = plan.ipv6_reject_wan() {
        out.insert(Object::LegacyV6Reject(wan.to_owned()));
    }
    if !plan.mss.is_empty() {
        // A selector, a learned IP and its reserve all share the physical
        // TCP handshake. Claim one pair per family and authenticated link.
        let mut tunnels = BTreeSet::new();
        if plan.go_ipv4 && plan.legacy_full.is_none() {
            // AWG2_MULTI prepares all authenticated links, including a live
            // reserve before it becomes the selected interface of a zone.
            tunnels.extend(plan.mss.keys().map(|iface| (iface.as_str(), Family::V4)));
        } else {
            for (selector, primary) in plan.flows() {
                if let Some(iface) = plan.effective(selector, primary) {
                    tunnels.insert((iface, selector.dest.family()));
                    if matches!(
                        plan.legacy_full,
                        Some(
                            super::plan::LegacyFull::Dual
                                | super::plan::LegacyFull::ForwardReject { .. }
                        )
                    ) {
                        tunnels.insert((iface, Family::V6));
                    }
                }
            }
        }
        for (iface, family) in tunnels {
            if let Some(&n) = plan.mss.get(iface) {
                let scope = Selector {
                    source: family.any(),
                    dest: family.any(),
                };
                for rule in [Firewall::MssOut(n), Firewall::MssIn(n)] {
                    out.insert(Object::Firewall(scope, iface.to_owned(), rule));
                }
            }
        }
    }
    if !plan.marks.is_empty() {
        super::marked::objects(plan, &mut out);
    }
    if let Some(iface) = plan.probe_iface() {
        out.insert(Object::ProbeLookup(iface.into()));
        out.insert(Object::Route(
            PROBE_IP.parse().expect("IPv6 probe"),
            iface.into(),
            PROBE_TABLE,
        ));
    }
    for bridge in &plan.dns_bridges {
        for family in [Family::V4, Family::V6].into_iter().filter(|f| {
            *f == Family::V4 || plan.legacy_full != Some(super::plan::LegacyFull::Ipv4Only)
        }) {
            for protocol in ["udp", "tcp"] {
                out.insert(Object::Redirect(family, bridge.clone(), protocol));
            }
        }
    }
    for (sel, i) in plan.flows() {
        if !plan.marks.is_empty() {
            break;
        }
        if (plan.killswitch || plan.temporary_stops.contains(&sel))
            && plan.full_endpoints.is_none()
        {
            out.insert(Object::Stop(sel, plan.ordered_default));
        }
        let Some(i) = plan.effective(sel, i) else {
            continue;
        };
        let table = if plan.scoped.is_empty() {
            if plan.full_sources.is_empty() {
                out.insert(
                    if plan.packed || plan.full_endpoints.is_some() || plan.ordered_default {
                        Object::PackedLookup(sel.dest.family())
                    } else {
                        Object::Rule(sel.dest.family())
                    },
                );
            }
            17842
        } else {
            let table = SCOPED_BASE + u16::from(plan.scoped_slot(i));
            out.insert(Object::Scoped(sel, table, plan.ordered_default));
            table
        };
        out.insert(Object::Route(sel.dest, i.to_owned(), table));
        if plan.packed {
            let family = sel.dest.family();
            out.insert(Object::Set(family, i.to_owned()));
            out.insert(Object::SetMember(sel.dest, i.into()));
            for &fw in Firewall::legacy_rules(plan) {
                out.insert(Object::SetFirewall(family, i.to_owned(), fw));
            }
            continue;
        }
        let xt: &[Firewall] = match plan.firewall {
            Backend::Legacy => Firewall::legacy_rules(plan),
            // Forwarding replies already pass through fw3/fw4's established/related rule.
            Backend::Fw3 => &[Firewall::Nat, Firewall::Clamp],
            Backend::Fw4 => &[],
        };
        for &rule in xt {
            if plan.full_sources.is_empty() {
                out.insert(Object::Firewall(sel, i.to_owned(), rule));
            } else {
                for &source in &plan.full_sources {
                    out.insert(Object::Firewall(
                        Selector { source, ..sel },
                        i.to_owned(),
                        rule,
                    ));
                }
            }
        }
        if plan.firewall == Backend::Fw3 {
            out.insert(Object::Fw3Forward(
                sel,
                i.to_owned(),
                fw3_forward_chain(plan.fw4_zone.as_deref()),
            ));
        } else if plan.firewall == Backend::Fw4 {
            for rule in super::fw4::rules(plan.fw4_zone.as_deref()) {
                out.insert(Object::Native(sel, i.to_owned(), rule));
            }
        }
    }
    if let Some(scope) = &plan.legacy_scope {
        scope.objects(plan, &mut out);
    }
    out
}
fn after<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|s| *s == key)
        .and_then(|i| tokens.get(i + 1))
        .copied()
}

pub(super) fn normalize_firewall_rule(family: Family, line: &str) -> String {
    let line = line
        .replace(&format!("\"{TAG}\""), TAG)
        .replace("ESTABLISHED,RELATED", "RELATED,ESTABLISHED");
    if family != Family::V6 {
        return line;
    }
    // Some ip6tables printers omit /128 on host selectors.
    let mut address = false;
    let mut result = String::with_capacity(line.len() + 8);
    for word in line.split_ascii_whitespace() {
        if !result.is_empty() {
            result.push(' ');
        }
        if address {
            let Ok(prefix) = word.parse::<Prefix>() else {
                return line;
            };
            if prefix.family() != family {
                return line;
            }
            use std::fmt::Write;
            write!(result, "{prefix}").unwrap();
        } else {
            result.push_str(word);
        }
        address = matches!(word, "-s" | "-d");
    }
    result
}
fn competing_dns_redirect(line: &str, bridges: &BTreeSet<&str>) -> bool {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    fields.starts_with(&["-A", "PREROUTING"])
        && after(&fields, "--dport") == Some("53")
        && matches!(after(&fields, "-j"), Some("DNAT" | "REDIRECT"))
        && after(&fields, "-i").is_none_or(|input| {
            bridges.contains(input)
                || input
                    .strip_suffix('+')
                    .is_some_and(|prefix| bridges.iter().any(|br| br.starts_with(prefix)))
        })
}
fn go_table(value: &str) -> bool {
    value
        .parse::<u16>()
        .is_ok_and(|t| matches!(t, 900..=964 | 998))
}
pub(super) fn go_firewall(listing: &str) -> bool {
    listing.lines().any(|line| {
        if line.contains("AWG2_") || line.contains("nfqws2-awg2") {
            return true;
        }
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if words.iter().any(|token| {
            matches!(
                token.trim_matches('"'),
                "N2S_AWGPPE_IN" | "N2S_AWGPPE_FWD" | "N2S_AWGPPE_OUT"
            )
        }) {
            return true;
        }
        if after(&words, "--comment")
            .or_else(|| after(&words, "comment"))
            .is_some_and(|s| s.trim_matches('"').starts_with("awg2-"))
        {
            return true;
        }
        // Go's multi-tunnel hooks also install untagged DNS redirects and
        // unscoped forward, NAT and MSS rules for their physical interfaces.
        (!line.contains(TAG)
            && after(&words, "--dport") == Some("53")
            && after(&words, "--to-ports") == Some("5354"))
            || (!line.contains(TAG)
                && after(&words, "dport") == Some("53")
                && line.contains("redirect to :5354"))
            || (!line.contains(TAG)
                && ["-i", "-o"]
                    .iter()
                    .any(|k| after(&words, k).is_some_and(super::plan::iface_ok))
                && matches!(
                    after(&words, "-j"),
                    Some("ACCEPT" | "MASQUERADE" | "TCPMSS")
                ))
            || (!line.contains(TAG)
                && ["iifname", "oifname"].iter().any(|k| {
                    after(&words, k)
                        .is_some_and(|iface| super::plan::iface_ok(iface.trim_matches('"')))
                })
                && (words.contains(&"accept")
                    || words.contains(&"masquerade")
                    || line.contains("maxseg size set")))
    })
}
fn rule_prefix(value: &str, family: Family) -> Option<Prefix> {
    if value == "all" {
        Some(family.any())
    } else {
        value.parse().ok()
    }
}
pub(super) struct Kernel<'a> {
    pub run: &'a dyn Runner,
    pub deadline: Instant,
    pub ip: Cell<Option<(&'static str, bool)>>,
    pub nested_sockets: BTreeMap<u32, u32>,
    pub held_dns_lookups: BTreeSet<Object>,
}
impl Kernel<'_> {
    pub(super) fn track_sockets(&mut self, doc: &serde_json::Value, plan: &Plan) {
        super::routed_disable::track_withdrawn_socket(self, doc, plan);
        if let Some(inner) = plan.permanent_full_inner(doc) {
            if let Ok((mark, table)) = nfqws2_awg_profile::nested_socket_selector(&inner) {
                self.nested_sockets.insert(mark, table);
            }
        }
        // The watchdog can move the payload policy independently of the
        // managed sockets. Keep recognizing other configured nested peers'
        // exact 60/61 pair after their TUN stops carrying the blanket route.
        let Some(rows) = doc["servers"].as_array() else {
            return;
        };
        if plan.legacy_full.is_none() {
            if plan.full_endpoints.is_none() && !plan.ordered_default {
                self.track_split_nested(doc, plan, rows);
            }
            return;
        }
        let enabled = |row: &&serde_json::Value| {
            row["config"]["enabled"] == true && row["config"]["client"]["enabled"] == true
        };
        let active_ids: BTreeSet<_> = rows
            .iter()
            .filter(enabled)
            .filter_map(|row| row["id"].as_str())
            .collect();
        for (index, row) in rows.iter().enumerate() {
            if !enabled(&row)
                || row["config"]["client"]["double_tunnel_id"]
                    .as_str()
                    .is_none_or(|outer| row["id"] == outer || !active_ids.contains(outer))
            {
                continue;
            }
            let applied = &row["applied_config"];
            let wire = if applied.is_object() {
                applied
            } else {
                &row["config"]
            };
            let iface = wire["client_iface"]
                .as_str()
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("awg{index}"));
            if let Ok((mark, table)) = nfqws2_awg_profile::nested_socket_selector(&iface) {
                self.nested_sockets.insert(mark, table);
            }
        }
    }

    fn track_split_nested(
        &mut self,
        doc: &serde_json::Value,
        plan: &Plan,
        rows: &[serde_json::Value],
    ) {
        let Ok(graph) = nfqws2_awg_profile::FailoverGraph::load(doc) else {
            return;
        };
        let enabled =
            |cfg: &serde_json::Value| cfg["enabled"] == true && cfg["client"]["enabled"] == true;
        for (iface, expected) in &plan.targets {
            let Some((outer, _)) = graph.nested(&expected.id) else {
                continue;
            };
            let owned = rows.iter().any(|row| {
                row["id"] == expected.id
                    && enabled(&row["config"])
                    && row["config"]["client"]["rust_managed"] == true
            });
            if !owned
                || !rows
                    .iter()
                    .any(|row| row["id"] == outer && enabled(&row["config"]))
            {
                continue;
            }
            let Ok((_, outer_iface, outer_target)) = super::plan::profile(doc, rows, outer) else {
                continue;
            };
            let Ok((_, actual_iface, actual)) = super::plan::profile(doc, rows, &expected.id)
            else {
                continue;
            };
            if actual_iface == *iface
                && outer_iface != *iface
                && !outer_target.public_key.is_empty()
                && actual.public_key == expected.public_key
                && !actual.public_key.is_empty()
            {
                // Inventory still checks the exact lookup/prohibit pair. A
                // configured owner does not authorize other RPDB selectors.
                if let Ok((mark, table)) = nfqws2_awg_profile::nested_socket_selector(iface) {
                    self.nested_sockets.insert(mark, table);
                }
            }
        }
        if plan.prefixes.is_empty()
            || plan.packed
            || !plan.scoped.is_empty()
            || !plan.reserves.is_empty()
            || plan.prefixes.keys().any(|p| p.family() != Family::V4)
        {
            return;
        }
        for row in rows {
            let Some(id) = row["id"].as_str() else {
                continue;
            };
            if plan.targets.values().any(|target| target.id == id)
                || row["config"]["routing"]["active"] == true
                || graph.nested(id).is_none()
            {
                continue;
            }
            let Ok((_, iface, _)) = super::plan::profile(doc, rows, id) else {
                continue;
            };
            let Ok((mark, table)) = nfqws2_awg_profile::nested_socket_selector(&iface) else {
                continue;
            };
            if !self.nested_sockets.contains_key(&mark)
                && !self.nested_sockets.values().any(|other| *other == table)
                && nfqws2_awg_profile::owns_unselected_nested_socket(doc, id, &iface, self.deadline)
            {
                self.nested_sockets.insert(mark, table);
            }
        }
    }
    pub(super) fn ipv6_stack(&self) -> io::Result<bool> {
        // A missing binary or a failed netfilter read says nothing about whether
        // the kernel can still forward IPv6. Require a readable procfs witness.
        const STACK: &str = "test -r /proc/net/route && test -d /proc/sys/net || exit 1; if test -e /proc/net/ipv6_route || test -d /proc/sys/net/ipv6 || test -e /proc/net/if_inet6; then echo ipv6; else echo ipv4-only; fi";
        match self.call("sh", &["-c", STACK])?.trim() {
            "ipv6" => Ok(true),
            "ipv4-only" => Ok(false),
            _ => Err(err("не удалось определить семейства IP ядра")),
        }
    }
    /// A first trial may have no destination addresses yet (DNS masks). Check
    /// both available families even when the proposed plan owns zero objects.
    pub(super) fn check_go_handoff(&self) -> io::Result<()> {
        self.check_previous_policies(false, None)
    }

    pub(super) fn check_go_implicit_trial(&self, plan: &Plan) -> io::Result<()> {
        self.check_previous_policies(false, Some(plan))
    }

    pub(super) fn check_cold_static_empty(&self) -> io::Result<()> {
        self.check_previous_policies(true, None)
    }

    fn check_previous_policies(&self, require_native_empty: bool, trial: Option<&Plan>) -> io::Result<()> {
        const PROBE: &str = r#"
for d in /opt/etc/ndm/netfilter.d /etc/nfqws2-strategy; do
  for f in 90-awg2.sh 91-awg2-multi.sh 92-awg2-fw4.sh; do
    if test -e "$d/$f" || test -L "$d/$f"; then echo hook; exit 0; fi
  done
done
test -r /proc/net/route || exit 1
test ! -e /proc/net/ipv6_route || echo ipv6
nft_needed=0
if test -d /sys/module/nf_tables || { test -f /etc/openwrt_release && command -v fw4 >/dev/null 2>&1; }; then nft_needed=1; fi
for tool in iptables ip6tables; do
  case "$tool" in iptables) names=/proc/net/ip_tables_names;; ip6tables) names=/proc/net/ip6_tables_names;; esac
  legacy=$tool
  if command -v "$tool" >/dev/null 2>&1; then
    echo "$tool"
    version=$("$tool" -V) || exit 1
    case "$version" in *nf_tables*) nft_needed=1; legacy=$tool-legacy;; esac
  elif command -v "$tool-legacy" >/dev/null 2>&1; then
    echo "$tool"
    legacy=$tool-legacy
  fi
  test "$legacy" = "$tool" || echo "$tool:legacy"
  if test -e "$names"; then
    test -r "$names" || exit 1
    while IFS= read -r table; do
      case "$table" in nat|filter|mangle)
        command -v "$legacy" >/dev/null 2>&1 || exit 1
        echo "$tool:$table";;
      esac
    done < "$names"
  fi
done
if command -v ipset >/dev/null 2>&1; then echo ipset; fi
if test "$nft_needed" = 1; then command -v nft >/dev/null 2>&1 || exit 1; echo nft; fi"#;
        let capabilities = self.call("sh", &["-c", PROBE])?;
        let has = |name: &str| capabilities.lines().any(|s| s == name);
        let occupied = || {
            if require_native_empty {
                err("найдены маршруты или firewall другой политики AWG")
            } else {
                err("маршруты или firewall прежней панели ещё действуют; завершите её работу до применения зон")
            }
        };
        let owned_set = |name: &str| name.starts_with("n2srt4_") || name.starts_with("n2srt6_");
        let old_firewall = |listing: &str| {
            go_firewall(listing)
                || require_native_empty
                    && listing.lines().any(|line| {
                        line.split_ascii_whitespace().any(|word| {
                            let word = word.trim_matches('"');
                            matches!(
                                word,
                                TAG | super::marked::TAG | "n2s-awg-mac" | "n2s-awg-src"
                            ) || owned_set(word)
                        })
                    })
        };
        if has("hook") {
            return Err(occupied());
        }
        if !has("iptables") && !has("nft") {
            return Err(err("не удалось проверить firewall прежней панели"));
        }
        for family in [Family::V4, Family::V6] {
            if family == Family::V6 && !has("ipv6") {
                continue;
            }
            for command in [
                &["rule", "show"][..],
                &["route", "show", "table", "all"][..],
            ] {
                for line in self.listing(family, command)?.lines() {
                    let fields: Vec<_> = line.split_ascii_whitespace().collect();
                    let occupied_table = after(&fields, "lookup")
                        .or_else(|| after(&fields, "table"))
                        .is_some_and(|table| {
                            go_table(table)
                                || require_native_empty
                                    && table.parse::<u16>().is_ok_and(|id| {
                                        table == TABLE
                                            || (SCOPED_BASE..=PROBE_TABLE).contains(&id)
                                            || (18000..=18128).contains(&id)
                                    })
                        });
                    let occupied_priority = require_native_empty
                        && command[0] == "rule"
                        && matches!(fields.first(), Some(&"68:" | &"69:"));
                    if occupied_table || occupied_priority {
                        return Err(occupied());
                    }
                }
            }
            let xt = if has(&format!("{}:legacy", family.firewall())) {
                match family {
                    Family::V4 => "iptables-legacy",
                    Family::V6 => "ip6tables-legacy",
                }
            } else {
                family.firewall()
            };
            for table in ["nat", "filter", "mangle"] {
                if has(&format!("{}:{table}", family.firewall()))
                    && old_firewall(&self.call(xt, &["-w", "-t", table, "-S"])?)
                {
                    return Err(occupied());
                }
            }
        }
        // Terse output omits elements of unrelated sets, including geo lists.
        if has("nft") {
            if let Some(plan) = trial {
                super::handoff::nft_trial::verify(self, &objects(plan))?;
            } else if old_firewall(&self.call("nft", &["-t", "list", "ruleset"])?) {
                return Err(occupied());
            }
        }
        if require_native_empty
            && has("ipset")
            && self
                .call("ipset", &["list", "-name"])?
                .lines()
                .any(owned_set)
        {
            return Err(occupied());
        }
        Ok(())
    }
    pub(super) fn call(&self, program: &str, args: &[&str]) -> io::Result<String> {
        let program = if program == "ip" {
            self.ip.get().map_or("ip", |(p, _)| p)
        } else {
            program
        };
        self.run.run(program, args, self.deadline)
    }
    pub(super) fn firewall_backend(&self) -> io::Result<Backend> {
        const DETECT: &str = "if [ -f /etc/openwrt_release ]; then if command -v fw4 >/dev/null; then echo fw4; elif command -v fw3 >/dev/null; then echo fw3; else echo unsupported; fi; fi";
        match self.call("sh", &["-c", DETECT])?.trim() {
            "" => Ok(Backend::Legacy),
            "fw3" => Ok(Backend::Fw3),
            "fw4" => Ok(Backend::Fw4),
            _ => Err(err("не удалось определить штатный firewall OpenWrt")),
        }
    }
    pub fn select_firewall(&self, plan: &mut Plan) -> io::Result<()> {
        if plan.empty() {
            return Ok(());
        }
        plan.firewall = self.firewall_backend()?;
        if plan.firewall != Backend::Legacy {
            plan.mss.clear();
        }
        if (plan.full_endpoints.is_some()
            || plan.ordered_default
            || plan.go_multi_v6_reject.is_some())
            && plan.firewall != Backend::Legacy
        {
            return Err(err("полный туннель требует firewall Keenetic"));
        }
        if let Some(super::plan::LegacyFull::ForwardReject { wan, ipv6_endpoint }) =
            &mut plan.legacy_full
        {
            *wan = self.legacy_wan(*ipv6_endpoint)?;
        }
        if plan.packed && plan.firewall != Backend::Legacy {
            return Err(err(
                "большие динамические наборы поддерживаются на Keenetic",
            ));
        }
        plan.fw4_zone = self.lan_zone(plan.firewall)?;
        Ok(())
    }
    pub(super) fn legacy_wan(&self, ipv6_endpoint: bool) -> io::Result<String> {
        let family = if ipv6_endpoint {
            Family::V6
        } else {
            Family::V4
        };
        let rows = self.listing(family, &["route", "show", "table", "main"])?;
        let mut fallback = None;
        for row in rows.lines() {
            let w: Vec<_> = row.split_ascii_whitespace().collect();
            if w.first() != Some(&"default") {
                continue;
            }
            if let Some(dev) = after(&w, "dev").filter(|s| super::plan::LegacyFull::valid_wan(s)) {
                if w.contains(&"via") {
                    fallback = Some(dev.to_owned());
                    break;
                }
                fallback.get_or_insert_with(|| dev.to_owned());
            }
        }
        fallback.ok_or_else(|| err("нет основного WAN для защиты IPv6"))
    }
    pub(super) fn lan_zone(&self, firewall: Backend) -> io::Result<Option<String>> {
        let tool = match firewall {
            Backend::Legacy => return Ok(None),
            Backend::Fw3 => "fw3",
            Backend::Fw4 => "fw4",
        };
        let zone = self.call(tool, &["-q", "network", "lan"]).map_err(|_| {
            err("AWG: штатный firewall OpenWrt не нашёл активную зону логической сети lan")
        })?;
        let name = zone.strip_suffix('\n').unwrap_or(&zone);
        if name == "lan" {
            return Ok(None);
        }
        if !valid_zone(firewall, name) {
            return Err(err(
                "AWG: недопустимое имя зоны firewall логической сети lan",
            ));
        }
        Ok(Some(name.to_owned()))
    }
    pub fn check_lan_zone(&self, plan: &Plan) -> io::Result<()> {
        if self.lan_zone(plan.firewall)? != plan.fw4_zone {
            return Err(err("AWG: изменилась зона firewall логической сети lan"));
        }
        Ok(())
    }

    pub(super) fn retire_fw3_forward(
        &self,
        claims: &BTreeSet<Object>,
        zone: Option<&str>,
    ) -> io::Result<()> {
        let active = fw3_forward_chain(zone);
        for family in [Family::V4, Family::V6] {
            let mut retired = claims.iter().filter(|o| {
                matches!(o, Object::Fw3Forward(s, _, chain) if s.dest.family() == family && *chain != active)
            }).peekable();
            if retired.peek().is_none() {
                continue;
            }
            let raw = self.call(family.firewall(), &["-w", "-t", "filter", "-S"])?;
            let mut rules = BTreeMap::new();
            for line in raw.lines().filter(|line| line.contains(TAG)) {
                *rules
                    .entry(normalize_firewall_rule(family, line))
                    .or_insert(0) += 1;
            }
            for object in retired {
                let (_, chain, spec) = object.xtables().expect("fw3 forwarding rule");
                match rules.get(&format!("-A {chain} {}", spec.join(" "))) {
                    None => (),
                    Some(1) => self.mutate(object, false)?,
                    Some(_) => return Err(err("fw3: найдено повторяющееся правило AWG")),
                }
            }
        }
        Ok(())
    }
    pub(super) fn listing(&self, family: Family, cmd: &[&str]) -> io::Result<String> {
        let mut args = vec!["-o", "-N", family.flag()];
        args.extend_from_slice(cmd);
        if let Some((program, numeric)) = self.ip.get() {
            if !numeric {
                args.remove(1);
            }
            return self.run.run(program, &args, self.deadline);
        }
        let initial = self.run.run("ip", &args, self.deadline);
        if initial.is_ok() {
            self.ip.set(Some(("ip", true)));
            return initial;
        }
        // BusyBox cannot encode our table IDs or always print route protocols.
        // The full Entware 4.4 build supports both, but predates ip -Numeric.
        for program in ["/opt/libexec/ip-full", "ip"] {
            let Ok(version) = self.run.run(program, &["-V"], self.deadline) else {
                continue;
            };
            if !version.starts_with("ip utility, iproute2-") {
                continue;
            }
            if self.run.run(program, &["-N", "-V"], self.deadline).is_ok() {
                self.ip.set(Some((program, true)));
            } else {
                self.check_legacy_names()?;
                self.ip.set(Some((program, false)));
                args.remove(1);
            }
            return self.run.run(program, &args, self.deadline);
        }
        Err(err("для политики AWG установите ip-full (iproute2): BusyBox ip не поддерживает номера таблиц и протокол владения маршрутами"))
    }
    fn check_legacy_names(&self) -> io::Result<()> {
        // iproute2 uses names from these files when -Numeric is unavailable.
        // An alias for an owned table/protocol, or a numeric-looking alias
        // for someone else's entry, would make textual ownership ambiguous.
        const NAMES: &str = r#"for d in /etc/iproute2 /usr/lib/iproute2 /opt/etc/iproute2 /opt/usr/lib/iproute2; do for n in rt_tables rt_protos; do for f in "$d/$n" "$d/$n.d/"*.conf; do if test -f "$f"; then echo "$n"; cat "$f" || exit 1; fi; done; done; done"#;
        let names = self.call("sh", &["-c", NAMES])?;
        let mut tables = false;
        for line in names.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            match line {
                "" => continue,
                "rt_tables" => {
                    tables = true;
                    continue;
                }
                "rt_protos" => {
                    tables = false;
                    continue;
                }
                _ => (),
            }
            let mut fields = line.split_ascii_whitespace();
            let raw = fields.next().unwrap_or("");
            let name = fields.next().unwrap_or("");
            let id = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16)
            } else if raw.len() > 1 && raw.starts_with('0') {
                u32::from_str_radix(raw, 8)
            } else {
                raw.parse()
            }
            .ok();
            let reserved = if tables {
                id.is_some_and(|n| matches!(n, 900..=964 | 998 | 17842..=17907 | 18000..=18128))
                    || matches!(name, "local" | "main" | "default" | "unspec")
                        && !matches!(
                            (id, name),
                            (Some(255), "local")
                                | (Some(254), "main")
                                | (Some(253), "default")
                                | (Some(0), "unspec")
                        )
            } else {
                id == Some(242)
            };
            if reserved
                || id.is_none()
                || name.is_empty()
                || name.parse::<u32>().is_ok()
                || name.starts_with("0x")
                || fields.next().is_some()
            {
                return Err(err("псевдонимы iproute2 препятствуют проверке таблицы или протокола AWG: требуется ip с поддержкой -N"));
            }
        }
        Ok(())
    }
    pub fn mutate(&self, o: &Object, add: bool) -> io::Result<()> {
        let family = o.family();
        match o {
            Object::MarkFence(f, s) => return super::marked::fence::mutate(self, *f, *s, add),
            Object::FullGuard(g) => return g.mutate(self, add),
            Object::PackedLookup(_) | Object::LegacyLookup(..) => self.call(
                "ip",
                &[
                    family.flag(),
                    "rule",
                    if add { "add" } else { "del" },
                    "pref",
                    PREF,
                    "fwmark",
                    match o {
                        Object::LegacyLookup(_, true) => super::legacy_scope::TUNNEL,
                        Object::LegacyLookup(_, false) => super::legacy_scope::DEFAULT,
                        _ => "0/0x20000000",
                    },
                    "table",
                    TABLE,
                ],
            )?,
            Object::Rule(_) => self.call(
                "ip",
                &[
                    family.flag(),
                    "rule",
                    if add { "add" } else { "del" },
                    "pref",
                    PREF,
                    "table",
                    TABLE,
                ],
            )?,
            Object::MarkLookup(f, s) => self.call(
                "ip",
                &[
                    f.flag(),
                    "rule",
                    if add { "add" } else { "del" },
                    "pref",
                    PREF,
                    "fwmark",
                    &super::marked::masked(*s),
                    "table",
                    &super::marked::table(*s).to_string(),
                ],
            )?,
            Object::ProbeLookup(iface) => self.call(
                "ip",
                &[
                    "-6",
                    "rule",
                    if add { "add" } else { "del" },
                    "pref",
                    "66",
                    "to",
                    PROBE_IP,
                    "oif",
                    iface,
                    "table",
                    &PROBE_TABLE.to_string(),
                ],
            )?,
            Object::Scoped(s, _, bypass) | Object::Stop(s, bypass) => {
                let (src, dst) = (s.source.to_string(), s.dest.to_string());
                let stop = matches!(o, Object::Stop(..));
                let mut args = vec![
                    family.flag(),
                    "rule",
                    if add { "add" } else { "del" },
                    "pref",
                    if stop { STOP_PREF } else { PREF },
                    "from",
                    &src,
                    "to",
                    &dst,
                ];
                if *bypass {
                    args.extend(["fwmark", "0/0x20000000"]);
                }
                let table;
                if let Object::Scoped(_, id, _) = o {
                    table = id.to_string();
                    args.extend(["table", &table]);
                } else {
                    args.push("blackhole");
                }
                self.call("ip", &args)?
            }
            Object::Route(n, i, table) => self.call(
                "ip",
                &[
                    family.flag(),
                    "route",
                    if add { "add" } else { "del" },
                    "table",
                    &table.to_string(),
                    &n.to_string(),
                    "dev",
                    i,
                    "proto",
                    PROTO,
                ],
            )?,
            Object::LegacyClassifier(..)
            | Object::Native(..)
            | Object::Set(..)
            | Object::SetMember(..)
            | Object::Classifier(..) => {
                return Err(err("объект firewall требует пакетного изменения"))
            }
            Object::LegacyV6Reject(_)
            | Object::Firewall(..)
            | Object::Fw3Forward(..)
            | Object::SetFirewall(..)
            | Object::GroupFirewall(..)
            | Object::Redirect(..) => {
                let (t, c, spec) = o.xtables().unwrap();
                let insert = add && matches!(o, Object::LegacyV6Reject(_));
                let mut args = vec![
                    "-w",
                    "-t",
                    t,
                    if insert {
                        "-I"
                    } else if add {
                        "-A"
                    } else {
                        "-D"
                    },
                    c,
                ];
                if insert {
                    args.push("1");
                }
                args.extend(spec.iter().map(String::as_str));
                self.call(family.firewall(), &args)?
            }
        };
        Ok(())
    }
    pub fn inventory(
        &self,
        claims: &BTreeSet<Object>,
        check_legacy: bool,
    ) -> io::Result<BTreeSet<Object>> {
        self.inventory_for(claims, claims, check_legacy)
    }
    pub fn inventory_for(
        &self,
        claims: &BTreeSet<Object>,
        proposed: &BTreeSet<Object>,
        check_legacy: bool,
    ) -> io::Result<BTreeSet<Object>> {
        self.inventory_with_go(claims, proposed, check_legacy, false)
    }
    pub(super) fn before_go_stop(&self, plan: &Plan) -> io::Result<()> {
        self.inventory_with_go(&BTreeSet::new(), &objects(plan), true, true)?;
        Ok(())
    }
    pub(super) fn parked_guard_before_go_stop(
        &self,
        claims: &BTreeSet<Object>,
        proposed: &BTreeSet<Object>,
    ) -> io::Result<BTreeSet<Object>> {
        self.inventory_with_go(claims, proposed, true, true)
    }
    fn inventory_with_go(
        &self,
        claims: &BTreeSet<Object>,
        proposed: &BTreeSet<Object>,
        check_legacy: bool,
        go_running: bool,
    ) -> io::Result<BTreeSet<Object>> {
        let mut seen = BTreeSet::new();
        seen.extend(super::legacy_scope::inventory(
            self, claims, proposed, go_running,
        )?);
        seen.extend(super::marked::inventory(
            self,
            claims,
            proposed,
            go_running,
            check_legacy,
        )?);
        seen.extend(super::packed::inventory(self, claims, proposed)?);
        if claims
            .iter()
            .chain(proposed)
            .any(|o| matches!(o, Object::Native(..)))
        {
            seen.extend(super::fw4::inventory(self, claims, proposed, check_legacy)?);
        }
        for family in [Family::V4, Family::V6] {
            if claims.iter().chain(proposed).any(|o| o.family() == family) {
                seen.extend(self.inventory_family(
                    family,
                    claims,
                    proposed,
                    check_legacy,
                    go_running,
                )?);
            }
        }
        super::packed::check_references(self, &seen)?;
        Ok(seen)
    }
    fn inventory_family(
        &self,
        family: Family,
        claims: &BTreeSet<Object>,
        proposed: &BTreeSet<Object>,
        check_legacy: bool,
        go_running: bool,
    ) -> io::Result<BTreeSet<Object>> {
        let tables: BTreeSet<_> = claims
            .iter()
            .chain(proposed)
            .filter(|o| o.family() == family)
            .filter_map(Object::table)
            .chain([17842])
            .collect();
        let mut seen = BTreeSet::new();
        let protected: Vec<_> = proposed
            .iter()
            .filter_map(|o| match o {
                Object::Stop(s, _) if s.dest.family() == family => Some(*s),
                _ => None,
            })
            .collect();
        let check_stop = !protected.is_empty()
            || claims
                .iter()
                .any(|o| o.family() == family && matches!(o, Object::Stop(..)));
        let full = claims
            .iter()
            .chain(proposed)
            .any(|o| matches!(o,Object::FullGuard(g) if g.family()==family));
        let mut take = |item: Object| {
            if !check_legacy && !claims.contains(&item) {
                return Ok(());
            }
            if !claims.contains(&item) || !seen.insert(item) {
                Err(err(
                    "зарезервированные таблица, приоритет или правило AWG заняты чужой записью",
                ))
            } else {
                Ok(())
            }
        };
        let rules = self.listing(family, &["rule", "show"])?;
        let nested = if check_legacy {
            super::full::socket_pairs(&rules, &self.nested_sockets)?
        } else {
            BTreeSet::new()
        };
        for l in rules.lines() {
            if nested.contains(l) {
                continue;
            }
            let w: Vec<_> = l.split_ascii_whitespace().collect();
            let lookup = after(&w, "lookup").or_else(|| after(&w, "table"));
            if family == Family::V6 && tables.contains(&PROBE_TABLE) && w.first() == Some(&"66:") {
                match w.as_slice() {
                    ["66:", "from", "all", "to", dst, "oif", iface, flags @ .., "lookup", "17907"]
                        if dst.parse::<Prefix>().ok() == PROBE_IP.parse::<Prefix>().ok()
                            && super::plan::iface_ok(iface)
                            && (flags.is_empty() || flags == ["[detached]"]) =>
                    {
                        take(Object::ProbeLookup((*iface).into()))?
                    }
                    _ if check_legacy => {
                        return Err(err("приоритет IPv6-пробы AWG занят другой политикой"))
                    }
                    _ => (),
                }
                continue;
            }
            if full && w.first() == Some(&"67:") {
                if let Some(rule) = super::full::main_rule(&w, family) {
                    take(Object::FullGuard(rule))?;
                } else if check_legacy {
                    return Err(err(
                        "приоритет защиты подключённых сетей занят другой политикой",
                    ));
                }
                continue;
            }
            if check_stop && w.first() == Some(&"69:") {
                let selector = match w.as_slice() {
                    ["69:", "from", source, "to", dest, mark @ .., "blackhole" | "6"]
                        if mark.is_empty()
                            || matches!(mark, ["fwmark", "0/0x20000000" | "0x0/0x20000000"]) =>
                    {
                        rule_prefix(source, family)
                            .zip(rule_prefix(dest, family))
                            .map(|(source, dest)| {
                                Object::Stop(Selector { source, dest }, !mark.is_empty())
                            })
                    }
                    _ => None,
                };
                if let Some(s) = selector {
                    take(s)?;
                } else if check_legacy {
                    return Err(err("приоритет защиты AWG занят другой политикой"));
                }
                continue;
            }
            if check_legacy
                && (!protected.is_empty() || full)
                && w.first()
                    .and_then(|p| p.trim_end_matches(':').parse::<u32>().ok())
                    .is_some_and(|p| p < 68)
                && !matches!(
                    w.as_slice(),
                    ["0:", "from", "all", "lookup", "local" | "255"]
                )
            {
                let disjoint = !w.contains(&"not")
                    && protected.iter().all(|s| {
                        after(&w, "from")
                            .and_then(|v| rule_prefix(v, family))
                            .is_some_and(|p| !p.overlaps(s.source))
                            || after(&w, "to")
                                .and_then(|v| rule_prefix(v, family))
                                .is_some_and(|p| !p.overlaps(s.dest))
                    });
                if !disjoint || full {
                    return Err(err(
                        "правило более высокого приоритета может обойти защиту AWG",
                    ));
                }
            }
            if w.first() == Some(&"68:")
                || lookup
                    .and_then(|t| t.parse().ok())
                    .is_some_and(|t| tables.contains(&t))
            {
                let matched = match w.as_slice() {
                    ["68:", "from", "all", "fwmark", mark, "lookup", tab]
                        if super::marked::slot(mark, tab).is_some() =>
                    {
                        Some(Object::MarkLookup(
                            family,
                            super::marked::slot(mark, tab).unwrap(),
                        ))
                    }
                    ["68:", "from", "all", "lookup", TABLE] => Some(Object::Rule(family)),
                    ["68:", "from", "all", "fwmark", m, "lookup", TABLE]
                        if matches!(
                            *m,
                            super::legacy_scope::DEFAULT
                                | "0x0/0x30000000"
                                | super::legacy_scope::TUNNEL
                        ) =>
                    {
                        Some(Object::LegacyLookup(
                            family,
                            *m == super::legacy_scope::TUNNEL,
                        ))
                    }
                    ["68:", "from", "all", "fwmark", "0/0x20000000" | "0x0/0x20000000", "lookup", TABLE] => {
                        Some(Object::PackedLookup(family))
                    }
                    ["68:", "from", src, "fwmark", "0/0x20000000" | "0x0/0x20000000", "lookup", TABLE] => {
                        src.parse::<Prefix>()
                            .ok()
                            .filter(|p| !p.any() && p.family() == family)
                            .map(|p| Object::FullGuard(super::full::Guard::SourceLookup(p)))
                    }
                    ["68:", "from", src, "to", dst, mark @ .., "lookup", tbl]
                        if mark.is_empty()
                            || matches!(mark, ["fwmark", "0/0x20000000" | "0x0/0x20000000"]) =>
                    {
                        let source = if *src == "all" {
                            Some(family.any())
                        } else {
                            src.parse().ok()
                        };
                        source.zip(dst.parse().ok()).zip(tbl.parse().ok()).map(
                            |((source, dest), t)| {
                                Object::Scoped(Selector { source, dest }, t, !mark.is_empty())
                            },
                        )
                    }
                    _ => None,
                };
                match matched {
                    Some(item) => take(item)?,
                    None if check_legacy => {
                        return Err(err("конфликт политики AWG с существующим ip rule"))
                    }
                    None => (),
                }
            }
            if check_legacy && !go_running && lookup.is_some_and(go_table) {
                return Err(err(
                    "найдена действующая политика прежней панели; она сохранена",
                ));
            }
        }
        for l in self
            .listing(family, &["route", "show", "table", "all"])?
            .lines()
        {
            let w: Vec<_> = l.split_ascii_whitespace().collect();
            let Some(table) = after(&w, "table")
                .and_then(|v| v.parse().ok())
                .filter(|v| tables.contains(v))
            else {
                continue;
            };
            if table == 17842 {
                match super::full::route(family, &w) {
                    Ok(Some(g)) => {
                        take(Object::FullGuard(g))?;
                        continue;
                    }
                    Ok(None) => (),
                    Err(_) if !check_legacy => continue,
                    Err(e) => return Err(e),
                }
            }
            if (18000..=18128).contains(&table) && matches!(w.first(), Some(&"blackhole" | &"6")) {
                match super::marked::fence::parse(family, table, &w) {
                    Ok(fence) => take(fence)?,
                    Err(_) if !check_legacy => (),
                    Err(error) => return Err(error),
                }
                continue;
            }
            let n = match w
                .first()
                .copied()
                .map(|s| {
                    if s == "default" {
                        Ok(family.any())
                    } else {
                        s.parse::<Prefix>()
                    }
                })
                .unwrap_or_else(|| Err(err("пустая запись маршрута AWG")))
            {
                Ok(v) => v,
                Err(_) if !check_legacy => continue,
                Err(e) => return Err(e),
            };
            let Some(i) = after(&w, "dev") else {
                if !check_legacy {
                    continue;
                }
                return Err(err("повреждён маршрут в таблице AWG"));
            };
            if after(&w, "proto") != Some(PROTO) {
                if !check_legacy {
                    continue;
                }
                return Err(err("в таблице AWG присутствует маршрут другого владельца"));
            }
            // A disappeared carrier can leave a linkdown route on its old TUN.
            // It still belongs to this receipt and can be removed by exact match.
            let attrs = w[1..].strip_suffix(&["linkdown"]).unwrap_or(&w[1..]);
            let mut attrs = attrs.chunks_exact(2);
            if !attrs.all(|a| {
                matches!(
                    a,
                    ["dev", _] | ["table", _] | ["proto", _] | ["scope", "link"] | ["scope", "253"]
                ) || family == Family::V6
                    && matches!(a, ["metric", "1024"] | ["pref", "medium" | "0"])
            }) || !attrs.remainder().is_empty()
            {
                if !check_legacy {
                    continue;
                }
                return Err(err("неизвестные атрибуты маршрута в таблице AWG"));
            }
            take(Object::Route(n, i.into(), table))?;
        }
        let mut tables = BTreeSet::new();
        let mut redirects = BTreeSet::new();
        for object in claims
            .iter()
            .chain(proposed)
            .filter(|o| o.family() == family)
        {
            match object {
                Object::Firewall(_, _, fw)
                | Object::SetFirewall(_, _, fw)
                | Object::GroupFirewall(_, _, _, _, fw) => {
                    tables.insert(fw.location().0);
                }
                Object::Redirect(_, br, _) => {
                    tables.insert("nat");
                    redirects.insert(br.as_str());
                }
                Object::LegacyV6Reject(_) | Object::Fw3Forward(..) => {
                    tables.insert("filter");
                }
                _ => (),
            }
        }
        if tables.is_empty() {
            return Ok(seen);
        }
        let mut expected = BTreeMap::new();
        for object in claims.iter().filter(|o| o.family() == family) {
            if let Some((table, chain, spec)) = object.xtables() {
                expected.insert((table, format!("-A {chain} {}", spec.join(" "))), object);
            }
        }
        for table in tables {
            for line in self
                .call(family.firewall(), &["-w", "-t", table, "-S"])?
                .lines()
            {
                if check_legacy && !go_running && line.contains("AWG2_") {
                    return Err(err(
                        "обнаружены правила прежнего AWG; их нужно снять прежним владельцем",
                    ));
                }
                if !line.contains(TAG) {
                    if check_legacy
                        && table == "nat"
                        && !redirects.is_empty()
                        && competing_dns_redirect(line, &redirects)
                        && !(go_running
                            && super::handoff::go_dns_redirect(line)
                                .is_some_and(|(bridge, _)| redirects.contains(bridge)))
                    {
                        return Err(err(
                            "порт DNS на мосту LAN уже перенаправлен другим правилом",
                        ));
                    }
                    continue;
                }
                let key = (table, normalize_firewall_rule(family, line));
                match expected.get(&key) {
                    Some(object) => take((*object).clone())?,
                    None if check_legacy => {
                        return Err(err(
                            "в firewall обнаружено неизвестное правило с меткой AWG",
                        ))
                    }
                    None => (),
                }
            }
        }
        Ok(seen)
    }
    pub(super) fn guard_before_go_stop(
        &self,
        plan: &Plan,
        endpoints: &BTreeSet<IpAddr>,
    ) -> io::Result<()> {
        super::acceleration::preflight(self, plan)?;
        self.guard(plan, endpoints)
    }
    pub fn guard(&self, plan: &Plan, endpoints: &BTreeSet<IpAddr>) -> io::Result<()> {
        const ACCEL: &str = r#"
if ! command -v ndmc >/dev/null 2>&1 && command -v uci >/dev/null 2>&1; then
    c=$(uci show firewall) || exit 1
    printf '%s\n' "$c" | awk -F= '
        $2 == "defaults" {defaults=$1; next}
        defaults != "" && index($1, defaults ".") == 1 && $1 ~ /\.flow_offloading(_hw)?$/ {
            gsub(/\047/, "", $2)
            if ($2 ~ /^(1|on|true|yes)$/) print "on"
        }
    '
    if command -v fw4 >/dev/null; then
        f=$(nft list chain inet fw4 forward) || exit 1
        printf '%s\n' "$f" | awk '/flow (add|offload) @/ {print "on"}'
    fi
fi"#;
        if plan.flows().next().is_some() && !self.call("sh", &["-c", ACCEL])?.is_empty() {
            return Err(err("ускорение NAT/flow offload активно; для этой политики требуется обычный путь через ядро"));
        }
        for family in [Family::V4, Family::V6] {
            if !plan.uses_family(family) {
                continue;
            }
            if plan.full_endpoints.is_none() && !plan.ordered_default {
                self.guard_family(plan, family)?;
            } else if !plan.full_sources.is_empty() {
                super::full::source_probes(self, plan, family)?;
            }
        }
        for endpoint in endpoints {
            let family = Family::of(*endpoint);
            if !plan.uses_family(family) {
                continue;
            }
            let dest = endpoint.to_string();
            let mut lookup = vec![family.flag(), "route", "get", dest.as_str()];
            if plan.full_endpoints.is_some()
                || plan.ordered_default
                || plan.socket_bypass.contains(endpoint)
            {
                // A just-roamed peer may still be captured by the old default.
                // Verify its independent underlay before adding the new throw.
                lookup.extend(["mark", "0x20000000"]);
            }
            let route = self.call("ip", &lookup)?;
            let w: Vec<_> = route.split_ascii_whitespace().collect();
            if after(&w, "dev").is_none_or(|i| {
                plan.targets.contains_key(i)
                    || plan.socket_bypass.contains(endpoint) && (i == "lo" || i.starts_with("awg"))
            }) {
                return Err(err("транспортный адрес VPN не имеет отдельного маршрута"));
            }
        }
        Ok(())
    }
    fn guard_family(&self, plan: &Plan, family: Family) -> io::Result<()> {
        let addrs = self.call("ip", &["-o", family.flag(), "addr", "show"])?;
        for line in addrs.lines() {
            let w: Vec<_> = line.split_ascii_whitespace().collect();
            if let Some(v) = after(&w, family.inet()) {
                let prefix: Prefix = v.parse()?;
                if plan.overlaps_destination(prefix) {
                    return Err(err(
                        "политика пересекает адрес или подключённую сеть роутера",
                    ));
                }
            }
        }
        for line in self
            .listing(family, &["route", "show", "table", "main"])?
            .lines()
        {
            let mut words = line.split_ascii_whitespace();
            let first = words.next().unwrap_or_default();
            // ip -N prints the RTN_* number where older builds print its name.
            let dest = if matches!(
                first,
                "unicast"
                    | "blackhole"
                    | "unreachable"
                    | "prohibit"
                    | "throw"
                    | "1"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
            ) {
                words.next().unwrap_or_default()
            } else {
                first
            };
            if dest == "default" || dest == "0.0.0.0/0" || dest == "::/0" {
                continue;
            }
            let existing = dest
                .parse::<Prefix>()
                .map_err(|_| err("неизвестный вид маршрута в основной таблице маршрутов"))?;
            // Keep a configured standby's exact underlay host route intact.
            // The RPDB selects our packed table for ordinary clients. The
            // marked AWG socket is checked separately against the live WAN.
            if plan
                .socket_bypass
                .iter()
                .any(|ip| Prefix::host(*ip) == existing)
                && first == dest
                && after(&line.split_ascii_whitespace().collect::<Vec<_>>(), "dev")
                    .is_some_and(|iface| iface != "lo" && !iface.starts_with("awg"))
            {
                continue;
            }
            if plan.overlaps_destination(existing) {
                return Err(err(
                    "политика пересекает существующий маршрут основной таблицы",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn verify_ipv6_reject(&self, plan: &Plan) -> io::Result<()> {
        if let Some(wan) = plan.ipv6_reject_wan() {
            let f = self.call("ip6tables", &["-w", "-t", "filter", "-S", "FORWARD"])?;
            let (_, _, spec) = Object::LegacyV6Reject(wan.to_owned()).xtables().unwrap();
            let expected = format!("-A FORWARD {}", spec.join(" "));
            if !f
                .lines()
                .find(|l| l.starts_with("-A FORWARD "))
                .is_some_and(|l| l.replace(&format!("\"{TAG}\""), TAG) == expected)
            {
                return Err(err(
                    "защита IPv6 AWG уступила первенство другому правилу FORWARD",
                ));
            }
        }
        Ok(())
    }
    pub fn verify_forward(&self, plan: &Plan) -> io::Result<()> {
        if let Some(scope) = &plan.legacy_scope {
            scope.verify_paths(self, plan)?;
        }
        if let Some(iface) = plan.probe_iface() {
            self.verify_probe_iface(iface)?;
        }
        self.verify_ipv6_reject(plan)?;
        for ip in &plan.socket_bypass {
            let reply = self.call(
                "ip",
                &[
                    Family::of(*ip).flag(),
                    "route",
                    "get",
                    &ip.to_string(),
                    "mark",
                    "0x20000000",
                ],
            )?;
            let words: Vec<_> = reply.split_ascii_whitespace().collect();
            if after(&words, "dev").is_none_or(|i| i == "lo" || i.starts_with("awg")) {
                return Err(err(
                    "фактический маршрут помеченного сокета не ведёт во внешнюю сеть",
                ));
            }
        }
        if let Some(endpoints) = &plan.full_endpoints {
            return super::full::verify(self, plan, endpoints);
        }
        if !plan.marks.is_empty() {
            return super::marked::verify(self, plan);
        }
        if plan.packed {
            return super::packed::verify(self, plan, None);
        }
        for family in [Family::V4, Family::V6] {
            if plan.flows().any(|(s, _)| s.dest.family() == family) {
                self.verify_family(plan, family)?;
            }
        }
        Ok(())
    }
    pub(super) fn verify_probe_iface(&self, iface: &str) -> io::Result<()> {
        let route = self.call("ip", &["-6", "route", "get", PROBE_IP, "oif", iface])?;
        let words = route.split_ascii_whitespace().collect::<Vec<_>>();
        if after(&words, "dev") != Some(iface) {
            return Err(err("IPv6-проба не привязана к подтверждённому AWG"));
        }
        Ok(())
    }

    fn verify_family(&self, plan: &Plan, family: Family) -> io::Result<()> {
        let addrs = if plan.scoped.is_empty() {
            String::new()
        } else {
            self.call("ip", &["-o", family.flag(), "addr", "show"])?
        };
        let mut lan = Vec::new();
        for line in addrs.lines() {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            if let [_, name, label, addr, ..] = words.as_slice() {
                if *label != family.inet() {
                    continue;
                }
                let iface = name.split('@').next().unwrap_or(name);
                if iface == "lo" || plan.targets.contains_key(iface) {
                    continue;
                }
                let Some((ip, _)) = addr.split_once('/') else {
                    continue;
                };
                if let (Ok(ip), Ok(prefix)) = (ip.parse::<IpAddr>(), addr.parse::<Prefix>()) {
                    lan.push((iface, ip, prefix));
                }
            }
        }
        for (sel, iface) in plan.flows().filter(|(s, _)| s.dest.family() == family) {
            let Some(iface) = plan.effective(sel, iface) else {
                continue;
            };
            let dest = sel.dest.sample().to_string();
            let route = if sel.source.any() {
                self.call("ip", &[family.flag(), "route", "get", &dest])?
            } else if let Some((input, src)) = lan.iter().find_map(|(name, ip, net)| {
                sel.source
                    .forwarded_sample(*net, *ip)
                    .map(|src| (*name, src))
            }) {
                self.call(
                    "ip",
                    &[
                        family.flag(),
                        "route",
                        "get",
                        &dest,
                        "from",
                        &src.to_string(),
                        "iif",
                        input,
                    ],
                )?
            } else if let Some((_, src, _)) =
                lan.iter().find(|(_, src, _)| sel.source.contains(*src))
            {
                self.call(
                    "ip",
                    &[
                        family.flag(),
                        "route",
                        "get",
                        &dest,
                        "from",
                        &src.to_string(),
                    ],
                )?
            } else {
                // A routed remote subnet has no local input address to probe; its
                // exact RPDB selector and FIB entry were verified by inventory.
                continue;
            };
            let f: Vec<_> = route.split_ascii_whitespace().collect();
            if after(&f, "dev") != Some(iface) {
                return Err(err("ядро выбрало другой интерфейс для адреса зоны"));
            }
        }
        Ok(())
    }
}
