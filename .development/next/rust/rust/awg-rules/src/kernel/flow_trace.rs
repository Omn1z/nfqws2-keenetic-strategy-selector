//! Read-only view of the last installed routing policy for conntrack tracing.
//! The receipt identifies the effective selector and peer. The current editor
//! document can decorate a matching generation but cannot decide its route.
use super::{
    boot_valid, dns, legacy_active,
    plan::{Family, LegacyFull, Plan, Selector},
    Journal, Prefix, Snapshot,
};
use crate::{model::ipish, Routing};
use nfqws2_store::Store;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
};

#[derive(Debug, PartialEq, Eq)]
pub enum FlowRoute<'a> {
    Unknown,
    Direct,
    Blocked,
    Tunnel { id: &'a str, iface: &'a str },
}

#[derive(Debug, PartialEq, Eq)]
pub struct FlowDecision<'a> {
    pub route: FlowRoute<'a>,
    pub rule: Option<usize>,
    pub name: Option<&'a str>,
    pub rule_owner: Option<&'a str>,
}

#[derive(Default)]
pub struct FlowSnapshot {
    state: State,
}

#[derive(Default)]
enum State {
    #[default]
    Unknown,
    Direct,
    Installed(Box<Installed>),
}

struct Installed {
    plan: Snapshot,
    sources: BTreeMap<Prefix, Prefix>,
    legacy_sources: BTreeSet<Prefix>,
    overlapping: bool,
    labels: Vec<Label>,
    expires: u64,
}

struct Label {
    rule: usize,
    name: String,
    owner: String,
    tunnel: bool,
    sources: BTreeSet<Prefix>,
    destinations: BTreeSet<Prefix>,
    catch_all: bool,
}

impl FlowSnapshot {
    /// Trust only a completed install from this boot. A trace never performs
    /// a peer check, resolution, route lookup or a kernel mutation here.
    pub fn read(db: &Store, boot: &str) -> io::Result<Self> {
        let journal = Journal::read(db)?;
        let doc = nfqws2_awg_profile::read(db)?;
        Self::project(db, journal, &doc, boot.trim(), nfqws2_awg_profile::now())
    }

    fn project(
        db: &Store,
        journal: Journal,
        doc: &Value,
        boot: &str,
        now: u64,
    ) -> io::Result<Self> {
        let owner = &doc["rust_static_routing"];
        if journal.idle() {
            return Ok(Self {
                state: if owner.is_object() || legacy_active(doc) {
                    State::Unknown
                } else {
                    State::Direct
                },
            });
        }

        let plan = journal.installed;
        if !boot_valid(boot)
            || journal.boot != boot
            || owner["boot"] != boot
            || owner["revision"].as_u64() != Some(plan.revision)
            || owner["pending_commit"].as_bool() != Some(journal.expires != 0)
            || legacy_active(doc)
            || !journal.preparing.is_empty()
            || journal.expires != 0 && now >= journal.expires
            || plan.empty()
        {
            return Ok(Self::default());
        }

        let sources = plan
            .source_ranges
            .iter()
            .flat_map(|(&class, ranges)| ranges.iter().map(move |&range| (range, class)))
            .collect();
        let legacy_sources = if let Some(scope) = &plan.legacy_scope {
            Prefix::compact(
                scope
                    .ingress_bindings()?
                    .into_iter()
                    .map(|(prefix, _)| prefix)
                    .collect(),
            )
        } else {
            BTreeSet::new()
        };
        let overlapping = plan
            .prefixes
            .keys()
            .zip(plan.prefixes.keys().skip(1))
            .any(|(a, b)| a.overlaps(*b));
        let labels = labels(db, doc, &plan).unwrap_or_default();
        Ok(Self {
            state: State::Installed(Box::new(Installed {
                plan,
                sources,
                legacy_sources,
                overlapping,
                labels,
                expires: journal.expires,
            })),
        })
    }

    pub fn classify(&self, source: IpAddr, destination: IpAddr) -> FlowDecision<'_> {
        let source = source.to_canonical();
        let destination = destination.to_canonical();
        if source.is_ipv4() != destination.is_ipv4() {
            return FlowDecision::new(FlowRoute::Unknown, None);
        }
        match &self.state {
            State::Unknown => FlowDecision::new(FlowRoute::Unknown, None),
            State::Direct => FlowDecision::new(FlowRoute::Direct, None),
            State::Installed(current)
                if current.expires == 0 || nfqws2_awg_profile::now() < current.expires =>
            {
                current.classify(source, destination)
            }
            State::Installed(_) => FlowDecision::new(FlowRoute::Unknown, None),
        }
    }
}

impl<'a> FlowDecision<'a> {
    fn new(route: FlowRoute<'a>, label: Option<&'a Label>) -> Self {
        Self {
            route,
            rule: label.map(|label| label.rule),
            name: label.map(|label| label.name.as_str()),
            rule_owner: label.map(|label| label.owner.as_str()),
        }
    }
}

impl Installed {
    fn selector(&self, source: IpAddr, destination: IpAddr) -> Option<(Selector, &str)> {
        let host = Prefix::host(destination);
        if !self.plan.prefixes.is_empty() {
            let (dest, iface) = if self.overlapping {
                host.ancestors()
                    .filter_map(|dest| self.plan.prefixes.get_key_value(&dest))
                    .last()
            } else {
                self.plan
                    .prefixes
                    .range(..=host)
                    .next_back()
                    .filter(|(dest, _)| dest.contains(destination))
            }?;
            return Some((
                Selector {
                    source: host.family().any(),
                    dest: *dest,
                },
                iface,
            ));
        }
        if self.sources.is_empty() {
            // Non-packed scoped receipts have at most 512 disjoint pairs.
            return self
                .plan
                .scoped
                .iter()
                .find(|(selector, _)| {
                    selector.source.contains(source) && selector.dest.contains(destination)
                })
                .map(|(selector, iface)| (*selector, iface.as_str()));
        }
        let (_, class) = self
            .sources
            .range(..=Prefix::host(source))
            .next_back()
            .filter(|(prefix, _)| prefix.contains(source))?;
        let last = self.plan.scoped.partition_point(|(selector, _)| {
            *selector
                <= Selector {
                    source: *class,
                    dest: host,
                }
        });
        let (selector, iface) = self.plan.scoped.get(last.checked_sub(1)?)?;
        (selector.source == *class && selector.dest.contains(destination))
            .then_some((*selector, iface))
    }

    fn classify(&self, source: IpAddr, destination: IpAddr) -> FlowDecision<'_> {
        let plan = &self.plan;
        // The receipt knows the blocked egress but conntrack does not
        // report which interface the kernel would have selected.
        if destination.is_ipv6() && plan.go_multi_v6_reject.is_some() {
            return FlowDecision::new(FlowRoute::Unknown, None);
        }
        let label = self.labels.iter().find(|label| {
            (!plan.go_ipv4 || destination.is_ipv4())
                && (label.sources.is_empty() || contains(&label.sources, source))
                && (label.catch_all || contains(&label.destinations, destination))
        });
        if let Some(endpoints) = &plan.full_endpoints {
            if endpoints.contains(&destination)
                || full_exempt(destination)
                || plan.full_direct.iter().any(|p| p.contains(destination))
                || !plan.full_sources.is_empty()
                    && !plan.full_sources.iter().any(|p| p.contains(source))
            {
                return FlowDecision::new(FlowRoute::Direct, label.filter(|label| !label.tunnel));
            }
            // Conntrack does not report the ingress bridge for a per-client
            // legacy exception, nor the current WAN egress for its IPv6 guard.
            if contains(&self.legacy_sources, source)
                || destination.is_ipv6()
                    && matches!(plan.legacy_full, Some(LegacyFull::ForwardReject { .. }))
            {
                return FlowDecision::new(FlowRoute::Unknown, None);
            }
        }
        let Some((selector, primary)) = self.selector(source, destination) else {
            return FlowDecision::new(FlowRoute::Direct, label.filter(|label| !label.tunnel));
        };
        let primary_id = plan.targets[primary].id.as_str();
        let label = label.filter(|label| label.tunnel && label.owner == primary_id);
        let route = if let Some(iface) = plan.effective(selector, primary) {
            FlowRoute::Tunnel {
                id: &plan.targets[iface].id,
                iface,
            }
        } else if plan.protected(primary)
            || plan.full_endpoints.is_some() && selector.dest.family() == Family::V6
        {
            FlowRoute::Blocked
        } else {
            FlowRoute::Direct
        };
        FlowDecision::new(route, label)
    }
}

fn full_exempt(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => super::full::excluded_v4().any(|p| p.contains(address)),
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.segments()[..6] == [0; 6]
        }
    }
}

fn contains(nets: &BTreeSet<Prefix>, ip: IpAddr) -> bool {
    nets.range(..=Prefix::host(ip))
        .next_back()
        .is_some_and(|p| p.contains(ip))
}

fn label_policy(db: &Store, doc: &Value, plan: &Plan) -> io::Result<Option<Routing>> {
    if let Some(saved) = &plan.learned {
        return saved.routing().map(Some);
    }
    if doc["routing_revision"].as_u64().unwrap_or_default() != plan.revision {
        return Ok(None);
    }
    let policy = crate::sources::current(db, doc)?;
    Ok(
        (plan.local_sources == crate::sources::Generation::from_policy(doc, &policy)?)
            .then_some(policy),
    )
}

fn labels(db: &Store, doc: &Value, plan: &Plan) -> io::Result<Vec<Label>> {
    let Some(policy) = label_policy(db, doc, plan)? else {
        return Ok(Vec::new());
    };
    let mut labels = Vec::new();
    let learned = plan.learned.as_ref().map_or(&[][..], |s| &s.members);
    for (index, zone) in policy.zones.into_iter().enumerate() {
        if !zone.enabled || zone.waiting_for_connection {
            continue;
        }
        let mut destinations = zone
            .ips
            .iter()
            .chain(&zone.domains)
            .filter(|v| ipish(v))
            .map(|v| v.trim().parse::<Prefix>())
            .collect::<io::Result<BTreeSet<_>>>()?;
        if let Some(exact) = &plan.dns {
            for name in zone.domains.iter().filter_map(|v| dns::name(v).ok()) {
                if let Some(addresses) = exact.snapshot.answers.get(&name) {
                    destinations.extend(addresses.iter().copied().map(Prefix::host));
                }
            }
        }
        let start = learned.partition_point(|m| m.zone < index);
        for member in learned[start..].iter().take_while(|m| m.zone == index) {
            destinations.insert(Prefix::host(member.ip));
        }
        let catch_all =
            zone.dns_catch_all() && (plan.full_endpoints.is_some() || plan.ordered_default);
        if destinations.is_empty() && !catch_all {
            continue;
        }
        let sources = zone
            .source_ips
            .iter()
            .map(|v| v.trim().parse::<Prefix>())
            .collect::<io::Result<_>>()?;
        labels.push(Label {
            rule: index + 1,
            tunnel: zone.direction() == "tunnel",
            owner: zone.tunnel_id,
            name: zone.name,
            sources: Prefix::compact(sources),
            destinations: Prefix::compact(destinations),
            catch_all,
        });
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::plan::Target;
    use serde_json::json;

    const BOOT: &str = "12121212-1212-1212-1212-121212121212";
    const OLD_BOOT: &str = "12121212-1212-1212-1212-121212121213";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn target(id: &str) -> Target {
        Target {
            id: id.into(),
            public_key: "A".repeat(44),
            mtu: 1420,
        }
    }

    fn fixture() -> (tempfile::TempDir, Store, Value) {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let doc = json!({
            "routing_revision": 7,
            "routing": {"mode":"zones"},
            "rust_static_routing":{"revision":7,"boot":BOOT,"pending_commit":false},
            "servers":[{"id":"primary", "config":{"routing":{"zones":[
                {"name":"paused","enabled":false,"ips":["203.0.113.0/24"]},
                {"name":"direct","enabled":true,"route":"direct","ips":["203.0.113.20"]},
                {"name":"video","enabled":true,"ips":["203.0.113.0/24"]}
            ]}}}]
        });
        (dir, db, doc)
    }

    fn journal(plan: Plan) -> Journal {
        let installed: Snapshot = plan.into();
        Journal {
            boot: BOOT.into(),
            installed,
            ..Journal::default()
        }
    }

    #[test]
    fn uses_applied_peer_and_ordered_labels_without_claiming_the_edited_draft() {
        let (_dir, db, mut doc) = fixture();
        let source = ip("192.168.1.20");
        let destination = ip("203.0.113.77");
        let dest = Prefix::host(destination);
        let selector = Selector {
            source: Family::V4.any(),
            dest,
        };
        let mut plan = Plan {
            targets: BTreeMap::from([
                ("awg0".into(), target("primary")),
                ("awg1".into(), target("reserve")),
            ]),
            prefixes: BTreeMap::from([(dest, "awg0".into())]),
            reserves: vec![(selector, vec!["awg1".into()])],
            selected: vec![(selector, Some("awg1".into()))],
            revision: 7,
            ..Plan::default()
        };
        let applied = FlowSnapshot::project(&db, journal(plan.clone()), &doc, BOOT, 0).unwrap();
        let decision = applied.classify(source, destination);
        assert_eq!(
            decision.route,
            FlowRoute::Tunnel {
                id: "reserve",
                iface: "awg1"
            }
        );
        assert_eq!(decision.rule, Some(3));
        assert_eq!(decision.name, Some("video"));
        assert_eq!(decision.rule_owner, Some("primary"));
        let direct = applied.classify(source, ip("203.0.113.20"));
        assert_eq!(direct.route, FlowRoute::Direct);
        assert_eq!(direct.rule, Some(2));

        doc["routing_revision"] = json!(8);
        let applied = FlowSnapshot::project(&db, journal(plan.clone()), &doc, BOOT, 0).unwrap();
        let decision = applied.classify(source, destination);
        assert_eq!(
            decision.route,
            FlowRoute::Tunnel {
                id: "reserve",
                iface: "awg1"
            }
        );
        assert_eq!(decision.rule, None);

        plan.selected = vec![(selector, None)];
        let open = FlowSnapshot::project(&db, journal(plan.clone()), &doc, BOOT, 0).unwrap();
        assert_eq!(open.classify(source, destination).route, FlowRoute::Direct);
        plan.killswitch = true;
        let blocked = FlowSnapshot::project(&db, journal(plan), &doc, BOOT, 0).unwrap();
        assert_eq!(
            blocked.classify(source, destination).route,
            FlowRoute::Blocked
        );
    }

    #[test]
    fn packed_selectors_use_actual_source_class_membership_not_its_representative() {
        let (_dir, db, doc) = fixture();
        let class: Prefix = "192.168.1.0/24".parse().unwrap();
        let dest: Prefix = "203.0.113.0/24".parse().unwrap();
        let plan = Plan {
            targets: BTreeMap::from([("awg0".into(), target("primary"))]),
            scoped: vec![(
                Selector {
                    source: class,
                    dest,
                },
                "awg0".into(),
            )],
            packed: true,
            marks: BTreeMap::from([("awg0".into(), 1)]),
            source_ranges: BTreeMap::from([(
                class,
                vec![class, "192.168.3.0/24".parse().unwrap()],
            )]),
            revision: 7,
            ..Plan::default()
        };
        let applied = FlowSnapshot::project(&db, journal(plan), &doc, BOOT, 0).unwrap();
        let destination = ip("203.0.113.77");
        assert_eq!(
            applied
                .classify(ip("::ffff:192.168.3.4"), destination)
                .route,
            FlowRoute::Tunnel {
                id: "primary",
                iface: "awg0"
            }
        );
        assert_eq!(
            applied.classify(ip("192.168.2.4"), destination).route,
            FlowRoute::Direct
        );
    }

    #[test]
    fn stale_ownership_cannot_be_mistaken_for_an_applied_or_direct_decision() {
        let (_dir, db, mut doc) = fixture();
        let source = ip("192.168.1.20");
        let destination = ip("203.0.113.77");
        let plan = Plan {
            targets: BTreeMap::from([("awg0".into(), target("primary"))]),
            prefixes: BTreeMap::from([(Prefix::host(destination), "awg0".into())]),
            revision: 7,
            ..Plan::default()
        };
        let stale = FlowSnapshot::project(&db, journal(plan.clone()), &doc, OLD_BOOT, 0).unwrap();
        assert_eq!(
            stale.classify(source, destination).route,
            FlowRoute::Unknown
        );

        let mut changing = journal(plan.clone());
        changing.preparing.push(plan.clone().into());
        let changing = FlowSnapshot::project(&db, changing, &doc, BOOT, 0).unwrap();
        assert_eq!(
            changing.classify(source, destination).route,
            FlowRoute::Unknown
        );

        let mut trial = journal(plan);
        trial.expires = 2;
        doc["rust_static_routing"]["pending_commit"] = json!(true);
        let expired = FlowSnapshot::project(&db, trial, &doc, BOOT, 2).unwrap();
        assert_eq!(
            expired.classify(source, destination).route,
            FlowRoute::Unknown
        );

        doc["rust_static_routing"] = Value::Null;
        let idle = FlowSnapshot::project(&db, Journal::default(), &doc, BOOT, 0).unwrap();
        assert_eq!(idle.classify(source, destination).route, FlowRoute::Direct);
        doc["servers"][0]["config"]["routing"]["active"] = json!(true);
        let legacy = FlowSnapshot::project(&db, Journal::default(), &doc, BOOT, 0).unwrap();
        assert_eq!(
            legacy.classify(source, destination).route,
            FlowRoute::Unknown
        );
    }

    #[test]
    fn public_view_reads_the_installed_boot_receipt_without_rewriting_it() {
        let (_dir, db, _) = fixture();
        let destination = ip("203.0.113.77");
        let source = ip("192.168.1.10");
        let plan = Plan {
            prefixes: BTreeMap::from([(Prefix::host(destination), "awg0".into())]),
            targets: BTreeMap::from([("awg0".into(), target("awg0"))]),
            revision: 7,
            ..Plan::default()
        };
        let installed = journal(plan);
        db.transaction(|tx| {
            super::super::stamp(tx, &installed)?;
            tx.save_runtime_bounded(
                super::super::RECEIPT,
                &installed,
                super::super::RECEIPT_LIMIT,
            )
        })
        .unwrap();
        let before = Journal::read(&db).unwrap();
        let applied = FlowSnapshot::read(&db, &format!("{BOOT}\n")).unwrap();
        assert_eq!(
            applied.classify(source, destination).route,
            FlowRoute::Tunnel {
                id: "awg0",
                iface: "awg0"
            }
        );
        assert_eq!(Journal::read(&db).unwrap(), before);
    }
}
