use super::*;
use std::net::IpAddr;

pub(super) fn checked_ip(
    journal: &Journal,
    change: &RoutedMtuChange,
    endpoint: Option<SocketAddr>,
    forward: bool,
) -> io::Result<Option<IpAddr>> {
    if change.legacy_predecessor.is_some()
        || change.native_mtu_endpoint.is_some()
        || change.nested_mtu_before_recorded
    {
        let (before, after) = authorized_endpoints(change).ok_or_else(invalid)?;
        let selected = if forward { after } else { before };
        if change
            .legacy_predecessor
            .as_ref()
            .is_some_and(|old| old.endpoint != before)
            || before.is_ipv4() != after.is_ipv4()
            || endpoint != Some(selected)
        {
            return Err(invalid());
        }
        if full_pair(journal, change).is_none() {
            check_plans(journal, before.ip())?;
            if before.ip() != after.ip() {
                check_plans(journal, after.ip())?;
            }
            if let Some(edit) = &change.endpoint_edit {
                for pinned in edit.resolved_before.iter().chain(&edit.resolved_after) {
                    if pinned.ip() != before.ip() && pinned.ip() != after.ip() {
                        check_plans(journal, pinned.ip())?;
                    }
                }
            }
        }
        return Ok(Some(selected.ip()));
    }
    if change.combines_endpoint_mtu() {
        let (before, after) = edit_endpoints(change).ok_or_else(invalid)?;
        let selected = if forward { after } else { before };
        if endpoint != Some(selected) {
            return Err(invalid());
        }
        if full_pair(journal, change).is_none() {
            check_plans(journal, selected.ip())?;
            if (change.nested_outer.is_some() || direct_cross_family_pair(change))
                && before.ip() != after.ip()
            {
                let retiring = if forward { before } else { after };
                check_plans(journal, retiring.ip())?;
            }
        }
        return Ok(Some(selected.ip()));
    }
    if let Some(edit) = change.endpoint_edit.as_ref().filter(|_| named(change)) {
        let (before, after) = edit.sockets()?;
        let selected = if forward { after } else { before };
        if endpoint != Some(selected) {
            return Err(invalid());
        }
        let raw = if forward { &edit.after } else { &edit.before };
        let addresses = edit.pinned_addresses(raw).unwrap_or_default();
        for address in addresses {
            check_plans(journal, address.ip())?;
        }
        if addresses
            .iter()
            .all(|address| address.ip() != selected.ip())
        {
            check_plans(journal, selected.ip())?;
        }
        return Ok(Some(selected.ip()));
    }
    let Some((before, after)) =
        edit_endpoints(change).filter(|(before, after)| before.ip() != after.ip())
    else {
        return Ok(None);
    };
    let selected = endpoint
        .filter(|endpoint| [before, after].contains(endpoint))
        .ok_or_else(invalid)?;
    if full_pair(journal, change).is_none() {
        check_plans(journal, selected.ip())?;
    }
    Ok(Some(selected.ip()))
}

pub(super) fn full_pair(journal: &Journal, change: &RoutedMtuChange) -> Option<(IpAddr, IpAddr)> {
    if change.legacy_predecessor.is_some() {
        return None;
    }
    if let Some(endpoint) = change
        .native_mtu_endpoint
        .or_else(|| fixed_nested_mtu_endpoint(change))
    {
        let ip = endpoint.ip();
        let exact = |plan: &Plan| {
            native_single_full(plan)
                && (!change.nested_mtu_before_recorded
                    || plan.killswitch && plan.full_endpoints == journal.committed.full_endpoints)
                && plan.revision == change.revision
                && plan
                    .targets
                    .get(&change.iface)
                    .is_some_and(|target| target.id == change.id)
                && plan
                    .full_endpoints
                    .as_ref()
                    .is_some_and(|endpoints| endpoints.contains(&ip))
        };
        return (exact(&journal.committed)
            && (journal.installed.empty() || exact(&journal.installed)))
        .then_some((ip, ip));
    }
    let (before, after) = edit_endpoints(change)?;
    let combined = change.combines_endpoint_mtu();
    let legacy = journal.committed.legacy_full.as_ref();
    if combined && legacy.is_some() {
        return None;
    }
    match legacy {
        None => (),
        Some(
            plan::LegacyFull::ForwardReject {
                ipv6_endpoint: false,
                ..
            }
            | plan::LegacyFull::Dual,
        ) if before.is_ipv4() => (),
        _ => return None,
    }
    let matches_full = |plan: &Plan| {
        let forward_reject = matches!(
            plan.legacy_full,
            Some(plan::LegacyFull::ForwardReject {
                ipv6_endpoint: false,
                ..
            })
        );
        let settled = legacy == Some(&plan::LegacyFull::Dual)
            && forward_reject
            && plan.full_endpoints == journal.committed.full_endpoints;
        single_full_geometry(plan)
            && plan.go_ipv4 == forward_reject
            && (plan.legacy_full.as_ref() == legacy || settled)
            && plan.legacy_probe == legacy.is_some()
            && (!combined || native_single_full(plan))
            && plan
                .targets
                .get(&change.iface)
                .is_some_and(|target| target.id == change.id)
            && plan.revision == change.revision
    };
    ((before.ip() != after.ip() || combined)
        && before.is_ipv4() == after.is_ipv4()
        && !named(change)
        && change.nested_outer.is_none()
        && matches_full(&journal.committed)
        && (journal.installed.empty() || matches_full(&journal.installed)))
    .then_some((before.ip(), after.ip()))
}

fn single_full_geometry(plan: &Plan) -> bool {
    plan.full_endpoints.is_some()
        && plan.legacy_scope.is_none()
        && plan.learned.is_none()
        && plan.dns_bridges.is_empty()
        && !plan.ordered_default
        && plan.full_direct.is_empty()
        && plan.full_sources.is_empty()
        && plan.reserves.is_empty()
        && plan.targets.len() == 1
}

pub(super) fn native_single_full(plan: &Plan) -> bool {
    single_full_geometry(plan)
        && !plan.go_ipv4
        && plan.legacy_full.is_none()
        && !plan.legacy_probe
        && plan.local_sources.is_none()
        && plan.permanent_fences.is_empty()
}

pub(super) fn native_full_fenced_ipv6(plan: &Plan) -> Option<&str> {
    let v4 = plan::Family::V4.any();
    let v6 = plan::Family::V6.any();
    let iface = plan.prefixes.get(&v4)?;
    let selected = |dest| plan.effective(plan::Selector { source: dest, dest }, iface);
    (native_single_full(plan)
        && plan.prefixes.get(&v6) == Some(iface)
        && selected(v4) == Some(iface.as_str())
        && selected(v6).is_none())
    .then_some(iface.as_str())
}

pub(super) fn check_plans(journal: &Journal, addr: IpAddr) -> io::Result<()> {
    if !explicit(journal) {
        return Err(err(
            "смена IP конечной точки AWG доступна только для явных зон",
        ));
    }
    let endpoint = Prefix::host(addr);
    for plan in [&journal.committed, &journal.installed] {
        if plan.overlaps_destination(endpoint) || plan.socket_bypass.contains(&addr) {
            return Err(err(
                "новый IP конечной точки пересекает подтверждённую политику AWG",
            ));
        }
    }
    Ok(())
}

pub(super) fn explicit(journal: &Journal) -> bool {
    [&journal.committed, &journal.installed].iter().all(|plan| {
        plan.full_endpoints.is_none() && !plan.ordered_default && plan.legacy_full.is_none()
    })
}

pub(super) fn verify_wan(k: &Kernel<'_>, addr: IpAddr, wan: &[String]) -> io::Result<()> {
    verify_wan_on(k, addr, wan, false, None).map(drop)
}

pub(super) fn checks_consistent_wan(change: &RoutedMtuChange) -> bool {
    direct_cross_family_pair(change)
        || change.legacy_predecessor.is_some()
            && edit_endpoints(change)
                .is_some_and(|(before, after)| named(change) || before.ip() != after.ip())
}

pub(super) fn verify_consistent_wan(
    k: &Kernel<'_>,
    addr: IpAddr,
    wan: &[String],
) -> io::Result<()> {
    let plain = verify_wan_on(k, addr, wan, false, None)?;
    verify_wan_on(k, addr, wan, true, Some(&plain)).map(drop)
}

pub(super) fn verify_wan_on(
    k: &Kernel<'_>,
    addr: IpAddr,
    wan: &[String],
    marked: bool,
    expected_iface: Option<&str>,
) -> io::Result<String> {
    let text = addr.to_string();
    let mut args = vec![plan::Family::of(addr).flag(), "route", "get", &text];
    if marked {
        args.extend(["mark", "0x20000000"]);
    }
    let route = k.call("ip", &args)?;
    let netifd = if wan.is_empty() {
        Some(k.call("ubus", &["call", "network.interface", "dump"])?)
    } else {
        None
    };
    nfqws2_awg_profile::physical_wan(&route, addr, wan, netifd.as_deref())
        .filter(|dev| expected_iface.is_none_or(|expected| expected == *dev))
        .map(str::to_owned)
        .ok_or_else(|| err("новый IP конечной точки AWG не подтвердил маршрут через WAN"))
}

/// A negative result requires a readable route to an unsuitable device or
/// an independently verified absence of a usable FIB route.
pub(super) fn has_wan(k: &Kernel<'_>, addr: IpAddr, wan: &[String]) -> io::Result<bool> {
    let text = addr.to_string();
    let family = plan::Family::of(addr);
    match k.call("ip", &[family.flag(), "route", "get", &text]) {
        Ok(route) => {
            let netifd = if wan.is_empty() {
                Some(k.call("ubus", &["call", "network.interface", "dump"])?)
            } else {
                None
            };
            nfqws2_awg_profile::inspect_physical_wan(&route, addr, wan, netifd.as_deref())
                .map(|device| device.is_some())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::Other
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
            ) =>
        {
            let no_ipv6 = addr.is_ipv6() && k.ipv6_stack().ok() == Some(false);
            let denied = || {
                k.listing(family, &["route", "show", "table", "all", "match", &text])
                    .is_ok_and(|rows| routes_are_unusable(&rows, addr))
            };
            if no_ipv6 || denied() {
                Ok(false)
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

fn routes_are_unusable(rows: &str, addr: IpAddr) -> bool {
    rows.lines()
        .filter(|line| !line.trim().is_empty())
        .all(|line| {
            let mut words = line.split_ascii_whitespace();
            matches!(
                words.next(),
                Some("blackhole" | "prohibit" | "throw" | "unreachable" | "6" | "7" | "8" | "9")
            ) && words.next().is_some_and(|dest| {
                dest == "default"
                    || dest
                        .parse::<Prefix>()
                        .is_ok_and(|prefix| prefix.contains(addr))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn numeric_unusable_routes_require_only_matching_denials() {
        let endpoint = "192.0.2.9".parse().unwrap();
        for (name, code) in [
            ("blackhole", "6"),
            ("unreachable", "7"),
            ("prohibit", "8"),
            ("throw", "9"),
        ] {
            assert!(routes_are_unusable(
                &format!("{code} 192.0.2.0/24\n{name} default"),
                endpoint,
            ));
        }
        for rows in [
            "8 198.51.100.9",
            "8 invalid",
            "10 192.0.2.9",
            "8 192.0.2.9\ndefault dev wan0",
        ] {
            assert!(!routes_are_unusable(rows, endpoint));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the isolated Linux fixture with two veth interfaces"]
    fn routed_ip_edit_verifies_real_wan_for_both_families() {
        let k = kernel(&nfqws2_router_command::System);
        let wan = ["n2qa-wan".into()];
        for ip in ["192.0.2.9", "2001:db8:32::9"] {
            let ip = ip.parse().unwrap();
            verify_wan(&k, ip, &wan).unwrap();
            verify_consistent_wan(&k, ip, &wan).unwrap();
            assert!(verify_wan(&k, ip, &["n2qa-peer".into()]).is_err());
            assert!(has_wan(&k, ip, &wan).unwrap());
            assert!(!has_wan(&k, ip, &["n2qa-peer".into()]).unwrap());
        }
        for missing in ["198.51.100.9", "2001:db8:99::9"] {
            assert!(!has_wan(&k, missing.parse().unwrap(), &wan).unwrap());
        }
        assert!(verify_wan(&k, "198.51.100.9".parse().unwrap(), &wan).is_err());

        let address = "192.0.2.9";
        let table = "17791";
        let rule = [
            "pref",
            table,
            "fwmark",
            "0x20000000/0x20000000",
            "lookup",
            table,
        ];
        let route = ["table", table, "192.0.2.9/32", "dev", "n2qa-peer"];
        let configure = |kind, action, fields: &[&str]| {
            let mut args = vec!["-4", kind, action];
            args.extend_from_slice(fields);
            k.call("ip", &args).unwrap();
        };
        configure("route", "add", &route);
        configure("rule", "add", &rule);
        let allowed = ["n2qa-wan".into(), "n2qa-peer".into()];
        let parsed = address.parse().unwrap();
        let plain = verify_wan_on(&k, parsed, &allowed, false, None);
        let marked = verify_wan_on(&k, parsed, &allowed, true, None);
        let consistent = verify_consistent_wan(&k, parsed, &allowed);
        configure("rule", "del", &rule);
        configure("route", "del", &route);
        assert_eq!(plain.unwrap(), "n2qa-wan");
        assert_eq!(marked.unwrap(), "n2qa-peer");
        assert!(consistent.is_err());
        verify_consistent_wan(&k, parsed, &allowed).unwrap();

        let blocked_route = ["prohibit", "203.0.113.10/32"];
        configure("route", "add", &blocked_route);
        let blocked = has_wan(&k, "203.0.113.10".parse().unwrap(), &wan);
        configure("route", "del", &blocked_route);
        assert!(!blocked.unwrap());
    }

    #[test]
    fn routed_nested_cross_family_ip_edit_requires_saved_outer_identity() {
        use nfqws2_awg_profile::{RoutedEndpointEdit, RoutedMtuOuter};

        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let mut change = RoutedMtuChange {
            id: "primary".into(),
            iface: "awg0".into(),
            revision: 1,
            before: 1420,
            after: 1420,
            nested_outer: None,
            nested_endpoint: None,
            legacy_predecessor: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: None,
            endpoint_edit: Some(RoutedEndpointEdit {
                before: "198.51.100.10:443".into(),
                after: "[2001:db8::55]:51820".into(),
                previous_reserve: None,
                resolved_before: vec![],
                resolved_after: vec![],
            }),
        };
        assert!(valid(&change));
        change.nested_outer = Some(RoutedMtuOuter {
            id: "outer".into(),
            iface: "awg1".into(),
            peer_key_sha256: [1; 32],
        });
        assert!(valid(&change));
        let mut authority = Authority {
            change,
            public_key: String::new(),
            outer_key: None,
            recorded_nested_primary: None,
            endpoint_committed: false,
            retry_endpoint: None,
            full_endpoint_staged: false,
            keep_full_ipv6_fenced: false,
        };
        db.transaction(|tx| authority.save(tx)).unwrap();
        assert!(pending_mtu_edit(&db).is_err());
        authority.outer_key = Some(String::new());
        db.transaction(|tx| authority.save(tx)).unwrap();
        assert_eq!(read(&db).unwrap(), Some(authority));
    }

    #[test]
    fn paired_cross_family_edit_checks_each_endpoint_in_both_route_generations() {
        use nfqws2_awg_profile::{RoutedEndpointEdit, RoutedLegacyPredecessor, RoutedMtuOuter};

        let before: SocketAddr = "198.51.100.10:443".parse().unwrap();
        let after: SocketAddr = "[2001:db8::20]:51820".parse().unwrap();
        let change = RoutedMtuChange {
            id: "primary".into(),
            iface: "awg0".into(),
            revision: 1,
            before: 1420,
            after: 1360,
            nested_outer: Some(RoutedMtuOuter {
                id: "outer".into(),
                iface: "awg1".into(),
                peer_key_sha256: [1; 32],
            }),
            nested_endpoint: None,
            legacy_predecessor: None,
            native_mtu_endpoint: None,
            legacy_mtu_before_recorded: false,
            nested_mtu_before_recorded: false,
            implicit_before_mtu: None,
            endpoint_edit: Some(RoutedEndpointEdit {
                before: before.to_string(),
                after: after.to_string(),
                previous_reserve: None,
                resolved_before: vec![],
                resolved_after: vec![],
            }),
        };
        assert!(valid(&change));
        let mut direct = change.clone();
        direct.nested_outer = None;
        assert!(valid(&direct));
        let mut inherited = direct.clone();
        inherited.legacy_predecessor = Some(RoutedLegacyPredecessor {
            endpoint: before,
            receipt_sha256: [1; 32],
        });
        assert!(!valid(&inherited));
        for change in [&change, &direct] {
            for (selected, forward) in [(before, false), (after, true)] {
                assert_eq!(
                    checked_ip(&Journal::default(), change, Some(selected), forward).unwrap(),
                    Some(selected.ip())
                );
                for conflict in [before, after] {
                    let plan = Snapshot::from(Plan {
                        socket_bypass: [conflict.ip()].into(),
                        ..Plan::default()
                    });
                    let mut journal = Journal {
                        committed: plan.clone(),
                        ..Journal::default()
                    };
                    assert!(checked_ip(&journal, change, Some(selected), forward).is_err());
                    journal.installed = plan;
                    journal.committed = Snapshot::default();
                    assert!(checked_ip(&journal, change, Some(selected), forward).is_err());
                }
            }
        }
    }

    #[test]
    fn routed_ip_edit_rejects_catchall_eager_dns_and_standby_in_both_generations() {
        let dst = "198.51.100.21".parse().unwrap();
        let eager = dns::Saved {
            snapshot: DnsSnapshot {
                request: DnsRequest {
                    revision: 1,
                    names: vec!["vpn.example".into()],
                    dual_stack: vec![],
                    ipv6_only: vec![],
                },
                answers: [("vpn.example".into(), vec![dst])].into(),
            },
            source_hash: "fixture".into(),
        };
        let blocked = [
            Plan {
                full_endpoints: Some(BTreeSet::new()),
                ..Plan::default()
            },
            Plan {
                ordered_default: true,
                ..Plan::default()
            },
            Plan {
                socket_bypass: [dst].into(),
                ..Plan::default()
            },
            Plan {
                dns: Some(eager),
                ..Plan::default()
            },
        ];
        assert!(check_plans(&Journal::default(), dst).is_ok());
        for plan in blocked {
            let snapshot = Snapshot::from(plan);
            let mut journal = Journal {
                committed: snapshot.clone(),
                ..Journal::default()
            };
            assert!(check_plans(&journal, dst).is_err());
            journal.installed = snapshot;
            journal.committed = Snapshot::default();
            assert!(check_plans(&journal, dst).is_err());
        }
    }
}
