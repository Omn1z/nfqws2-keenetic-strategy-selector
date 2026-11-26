//! The Go watchdog may use the editor's selected profile until the next
//! restart. This runtime plan never replaces the confirmed plan in the journal.
use super::{err, io, legacy_scope, plan, Kernel, LivePeer, Plan, Prefix, Store, Value};
use crate::{model, policy};
use nfqws2_awg_profile::DIRECT_SOCKET_MARK;
use plan::{Family, Verification};
use std::net::IpAddr;

pub(super) struct Candidate {
    pub installed: Plan,
    pub rollback: Plan,
}

pub(super) fn scheduled(committed: &Plan, installed: &Plan) -> bool {
    committed.revision == installed.revision
        && committed.legacy_primary().is_some()
        && installed.legacy_primary().is_some()
}

pub(super) fn is_transient(committed: &Plan, installed: &Plan) -> bool {
    scheduled(committed, installed)
        && committed
            .legacy_primary()
            .zip(installed.legacy_primary())
            .is_some_and(|((_, a), (_, b))| a.id != b.id)
}

fn owner<'a>(doc: &'a Value, routing: &Plan) -> Option<&'a Value> {
    let (_, target) = routing.legacy_primary()?;
    doc["servers"]
        .as_array()?
        .iter()
        .find(|r| r["id"] == target.id)
}

fn eligible(row: &Value) -> bool {
    let config = &row["config"];
    config["enabled"] == true
        && config["client"]["enabled"] == true
        && config["client"]["standby"] != true
}

fn dns_bindings(plan: &mut Plan, ready: Option<&[String]>) -> io::Result<()> {
    let bridges = if plan.learned.is_some() {
        ready
            .filter(|names| !names.is_empty())
            .ok_or_else(|| err("нет подтверждённых LAN-слушателей DNS для выбранного профиля"))?
    } else {
        &[]
    };
    plan.set_dns_bridges(bridges)
}

fn intent(
    k: &Kernel<'_>,
    db: &Store,
    doc: &Value,
    current: &Plan,
    id: &str,
    ready: Option<&[String]>,
) -> io::Result<Plan> {
    let rows = doc["servers"]
        .as_array()
        .ok_or_else(|| err("нет списка серверов AWG"))?;
    let selected = model::selected_profile(doc).ok_or_else(|| err("нет выбранного туннеля AWG"))?;
    if !eligible(selected) {
        return Err(err("выбранный профиль не готов к смене полного туннеля"));
    }
    let mut next = current.clone();
    (next.legacy_scope, next.learned) = legacy_scope::rebuild(k, db, doc, current)?;
    dns_bindings(&mut next, ready)?;
    next.killswitch = policy::current(doc)?.killswitch;
    let (_, iface, target) = plan::profile(doc, rows, id)?;
    next.targets.clear();
    next.targets.insert(iface.clone(), target);
    for primary in next.prefixes.values_mut() {
        primary.clone_from(&iface);
    }
    next.offline.clear();
    next.selected.clear();
    next.mss.clear();
    next.validate()?;
    Ok(next)
}

fn direct_transport(k: &Kernel<'_>, live: &LivePeer) -> io::Result<IpAddr> {
    if !matches!(live.socket_mark, 0 | DIRECT_SOCKET_MARK) || live.nested_mtu.is_some() {
        return Err(err("внешний сокет AWG должен иметь прямой транспорт"));
    }
    let ip = live.endpoint.ip().to_canonical();
    let route = k.call(
        "ip",
        &[
            Family::of(ip).flag(),
            "route",
            "get",
            &ip.to_string(),
            "mark",
            "0x20000000",
        ],
    )?;
    let words: Vec<_> = route
        .lines()
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .collect();
    let device = words.windows(2).find(|w| w[0] == "dev").map(|w| w[1]);
    if device.is_none_or(|dev| dev == "lo" || dev.starts_with("awg")) {
        return Err(err("транспорт целевого пира не имеет независимого пути"));
    }
    Ok(ip)
}

fn nested_underlay(
    k: &Kernel<'_>,
    doc: &Value,
    inner: &Value,
    iface: &str,
    live: &LivePeer,
    permanent: bool,
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<IpAddr> {
    let missing = || err("внешний пир полного туннеля не подтверждён");
    let id = inner["config"]["client"]["double_tunnel_id"]
        .as_str()
        .ok_or_else(missing)?;
    let rows = doc["servers"].as_array().ok_or_else(missing)?;
    let outer = rows
        .iter()
        .find(|row| row["id"] == id)
        .ok_or_else(missing)?;
    let config = &outer["config"];
    if config["enabled"] != true
        || config["client"]["enabled"] != true
        || config["client"]["double_tunnel_mode"] == "permanent"
    {
        return Err(missing());
    }
    let (wire, outer_iface, _) = plan::profile(doc, rows, id)?;
    // The full-route resolver verifies the permanent mode itself. A client
    // in another mode can also be using its configured outer at this tick.
    if !permanent {
        plan::verify_nested_path(k, iface, &outer_iface, live)?;
    }
    let outer_peer = peer(wire, &outer_iface)?;
    let destination = live.endpoint.ip().to_canonical();
    let grants = outer_peer
        .allowed
        .iter()
        .map(|s| s.parse::<Prefix>())
        .collect::<io::Result<Vec<_>>>()?;
    if !grants.iter().any(|prefix| prefix.contains(destination)) {
        return Err(err(
            "AllowedIPs внешнего пира не покрывают адрес вложенного туннеля",
        ));
    }
    direct_transport(k, &outer_peer)
}

pub(super) fn resolve_legacy_transport(
    doc: &Value,
    mut routing: Plan,
    previous: Option<&Plan>,
    monitor: Verification<'_, '_>,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<plan::Resolution> {
    let (Verification::Read(k) | Verification::Refresh(k)) = monitor;
    let row = owner(doc, &routing)
        .filter(|r| eligible(r))
        .ok_or_else(|| err("нет действующего профиля полного туннеля"))?;
    let permanent = routing.permanent_full_inner(doc).is_some();
    routing.killswitch |= permanent;
    let mut outer_endpoint = None;
    let mut result =
        plan::resolve_on(doc, routing, true, previous, Some(monitor), |cfg, iface| {
            let live = peer(cfg, iface)?;
            if live.socket_mark >> 28 == 0xa {
                outer_endpoint = Some(nested_underlay(
                    k, doc, row, iface, &live, permanent, &mut peer,
                )?);
            } else if permanent {
                return Err(err("постоянный полный туннель ожидает вложенный сокет"));
            } else {
                direct_transport(k, &live)?;
            }
            Ok(live)
        })?;
    if let Some(endpoint) = outer_endpoint {
        result.plan.killswitch = true;
        result.endpoints.insert(endpoint);
        result.plan.full_endpoints = Some(result.endpoints.clone());
        result.plan.validate()?;
    }
    Ok(result)
}

fn authenticate(
    k: &Kernel<'_>,
    doc: &Value,
    routing: Plan,
    peer: &mut impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<plan::Resolution> {
    let mut result = resolve_legacy_transport(doc, routing, None, Verification::Refresh(k), peer)?;
    if !result.plan.fully_live() {
        return Err(err("нет подтверждённого пира для полного маршрута"));
    }
    k.select_firewall(&mut result.plan)?;
    k.guard(&result.plan, &result.endpoints)?;
    Ok(result)
}

fn park(old: &Plan) -> Plan {
    let mut parked = old.clone();
    let selectors = parked.flows().map(|(s, _)| s).collect::<Vec<_>>();
    parked.park(&selectors);
    parked.mss.clear();
    parked.legacy_scope = None;
    parked.learned = None;
    parked.dns_bridges.clear();
    parked
}

fn rollback(old: &Plan, checked: Option<&plan::Resolution>) -> Plan {
    let Some(checked) = checked else {
        return park(old);
    };
    if old.legacy_scope != checked.plan.legacy_scope
        || old.legacy_full != checked.plan.legacy_full
        || !old.killswitch && checked.plan.killswitch
        || !old
            .full_endpoints
            .as_ref()
            .is_some_and(|ips| checked.endpoints.is_subset(ips))
    {
        return park(&checked.plan);
    }
    let unavailable = old
        .flows()
        .filter_map(|(s, primary)| {
            (old.effective(s, primary).is_some()
                && checked
                    .plan
                    .prefixes
                    .get(&s.dest)
                    .and_then(|next| checked.plan.effective(s, next))
                    != Some(primary))
            .then_some(s)
        })
        .collect::<Vec<_>>();
    let mut rollback = old.clone();
    rollback.park(&unavailable);
    rollback
}

fn keep_transport(k: &Kernel<'_>, committed: &Plan, mut temporary: Plan) -> io::Result<Plan> {
    // The confirmed transport remains on the underlay during the temporary
    // switch, so its interface is still available to verify for compensation.
    if let (Some(primary), Some(current)) =
        (&committed.full_endpoints, &mut temporary.full_endpoints)
    {
        current.extend(primary.iter().copied());
    }
    temporary.validate()?;
    k.guard(&temporary, temporary.full_endpoints.as_ref().unwrap())?;
    Ok(temporary)
}

pub(super) fn candidate(
    db: &Store,
    k: &Kernel<'_>,
    doc: &Value,
    committed: &Plan,
    installed: &Plan,
    ready: Option<&[String]>,
    mut peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Option<Candidate>> {
    if !scheduled(committed, installed) {
        return Ok(None);
    }
    let (_, original) = committed.legacy_primary().unwrap();
    let (_, current) = installed.legacy_primary().unwrap();
    let selected = doc["active_id"].as_str().unwrap_or_default();
    let transient = original.id != current.id;
    if !transient && selected == current.id {
        return Ok(None);
    }
    // The previous route is authenticated independently, on its original
    // deployed configuration, before it may be used as compensation.
    let checked = authenticate(k, doc, installed.clone(), &mut peer).ok();
    let mut rollback = rollback(installed, checked.as_ref());
    if rollback.permanent_full_inner(doc).is_some() {
        rollback.killswitch = true;
    }
    let may_switch = doc["routing_revision"].as_u64().unwrap_or_default() == committed.revision
        && policy::current(doc)?.mode == "full";
    let current_live = installed.fully_live();
    let selected_plan = if may_switch && selected == current.id && checked.is_some() && current_live
    {
        checked.as_ref().map(|v| v.plan.clone())
    } else if may_switch && selected != original.id {
        let donor = if current_live { installed } else { committed };
        intent(k, db, doc, donor, selected, ready)
            .ok()
            .and_then(|p| authenticate(k, doc, p, &mut peer).ok())
            .map(|v| v.plan)
    } else {
        None
    };
    if let Some(installed) = selected_plan {
        let mut installed = keep_transport(k, committed, installed)?;
        dns_bindings(&mut installed, ready)?;
        return Ok(Some(Candidate {
            installed,
            rollback,
        }));
    }
    if !transient {
        return Ok(None);
    }
    let mut installed = if let Some(current) =
        checked.filter(|_| may_switch && selected != original.id && current_live)
    {
        // A failed selection of C cannot replace an independently verified B.
        keep_transport(k, committed, current.plan)?
    } else {
        authenticate(k, doc, committed.clone(), &mut peer)
            .ok()
            .map_or_else(|| rollback.clone(), |v| v.plan)
    };
    dns_bindings(&mut installed, ready)?;
    Ok(Some(Candidate {
        installed,
        rollback,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfqws2_router_command::Runner;
    use serde_json::json;
    use std::time::Instant;

    struct Router;

    impl Runner for Router {
        fn run(&self, command: &str, args: &[&str], _: Instant) -> io::Result<String> {
            match (command, args) {
                ("sh", ["-c", script]) => Ok(if script.contains("/proc/net/ipv6_route") {
                    "ipv6"
                } else {
                    ""
                }
                .into()),
                ("ip", ["-o", "-N", "-4", "route", "show", "table", "main"]) => {
                    Ok("default via 192.0.2.1 dev eth0".into())
                }
                ("ip", ["-4", "route", "get", _, "mark", "0x20000000"]) => {
                    Ok("via 192.0.2.1 dev eth0".into())
                }
                ("ip", ["-6", "addr", "show", "dev", _, "scope", "global"]) => {
                    Ok("inet6 2001:db8::20/64 scope global".into())
                }
                _ => panic!("unexpected watchdog verification command {command} {args:?}"),
            }
        }
    }

    fn fixture() -> (Value, Plan) {
        let config = |port, key: char, active| {
            json!({
                "endpoint":format!("198.51.100.{port}:51820"),
                "enabled":true,
                "client":{"enabled":true},
                "public_key":key.to_string().repeat(44),
                "routing":{"mode":"full","mtu":1420,"killswitch":true,"active":active}
            })
        };
        let a = config(10, 'a', true);
        let b = config(20, 'b', false);
        let draft = config(30, 'd', false);
        let doc = json!({"active_id":"b","routing_revision":9,
        "routing":{"mode":"full","killswitch":true},"servers":[
            {"id":"a","config":a}, {"id":"b","config":draft,"applied_config":b}
        ]});
        let primary = Plan {
            prefixes: [
                (Family::V4.any(), "awg0".into()),
                (Family::V6.any(), "awg0".into()),
            ]
            .into(),
            targets: [(
                "awg0".into(),
                plan::Target {
                    id: "a".into(),
                    public_key: "a".repeat(44),
                    mtu: 1420,
                },
            )]
            .into(),
            full_endpoints: Some(["198.51.100.10".parse().unwrap()].into()),
            legacy_full: Some(plan::LegacyFull::Dual),
            legacy_probe: true,
            killswitch: true,
            mss: [("awg0".into(), 1380)].into(),
            revision: 9,
            ..Default::default()
        };
        (doc, primary)
    }

    fn live(cfg: &Value, iface: &str) -> io::Result<LivePeer> {
        assert_eq!(
            cfg["public_key"],
            if iface == "awg0" {
                "a".repeat(44)
            } else {
                "b".repeat(44)
            }
        );
        Ok(LivePeer {
            ipv6_reachable: iface == "awg0",
            endpoint: cfg["endpoint"].as_str().unwrap().parse().unwrap(),
            allowed: vec!["0.0.0.0/0".into(), "::/0".into()],
            socket_mark: DIRECT_SOCKET_MARK,
            nested_mtu: None,
            prefer_ordinary: false,
            nested_transport: None,
            direct_backup: None,
            endpoint_predecessor: None,
            fresh_bound_ipv6_probe: None,
            active_replacement_peer: None,
        })
    }

    struct NestedRouter {
        outer: &'static str,
        prohibit: bool,
    }

    impl Runner for NestedRouter {
        fn run(&self, command: &str, args: &[&str], end: Instant) -> io::Result<String> {
            match (command, args) {
                ("ip", ["-o", "-N", "-4", "rule", "show"]) => {
                    let prohibit = if self.prohibit {
                        "\n61: from all fwmark 0xa0000001 8"
                    } else {
                        ""
                    };
                    Ok(format!(
                        "60: from all fwmark 0xa0000001 lookup 829{prohibit}"
                    ))
                }
                ("ip", ["-4", "route", "get", "198.51.100.20", "mark", "0xa0000001"]) => {
                    Ok(format!("198.51.100.20 dev {} table 829", self.outer))
                }
                _ => Router.run(command, args, end),
            }
        }
    }

    fn nested_fixture(mode: &str) -> (Value, Plan) {
        let (mut doc, mut a) = fixture();
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[1]["config"]["client"]["double_tunnel_id"] = json!("outer");
        rows[1]["config"]["client"]["double_tunnel_mode"] = json!(mode);
        let mut outer = rows[0]["config"].clone();
        outer["endpoint"] = json!("198.51.100.40:51820");
        outer["public_key"] = json!("c".repeat(44));
        rows.push(json!({"id":"outer","config":outer}));
        doc["routing"]["killswitch"] = json!(false);
        a.killswitch = false;
        (doc, a)
    }

    fn nested_peer(cfg: &Value, iface: &str) -> io::Result<LivePeer> {
        match iface {
            "awg0" => live(cfg, iface),
            "awg1" => Ok(LivePeer {
                socket_mark: 0xa0000001,
                nested_mtu: Some(1360),
                prefer_ordinary: false,
                nested_transport: None,
                direct_backup: None,
                endpoint_predecessor: None,
                fresh_bound_ipv6_probe: None,
                active_replacement_peer: None,
                ipv6_reachable: true,
                ..live(cfg, iface)?
            }),
            "awg2" => {
                assert_eq!(cfg["public_key"], "c".repeat(44));
                Ok(LivePeer {
                    ipv6_reachable: false,
                    nested_mtu: None,
                    prefer_ordinary: false,
                    nested_transport: None,
                    direct_backup: None,
                    endpoint_predecessor: None,
                    fresh_bound_ipv6_probe: None,
                    active_replacement_peer: None,
                    endpoint: "198.51.100.41:51820".parse().unwrap(),
                    allowed: vec!["198.51.100.20/32".into()],
                    socket_mark: DIRECT_SOCKET_MARK,
                })
            }
            _ => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    #[test]
    fn watchdog_switches_to_a_witnessed_nested_peer_and_preserves_both_family_fences() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(tmp.path()).unwrap();
        let router = NestedRouter {
            outer: "awg2",
            prohibit: true,
        };
        let mut k = super::super::kernel(&router);
        for mode in ["permanent", "automatic"] {
            let (mut doc, a) = nested_fixture(mode);
            k.track_sockets(&doc, &a);
            assert_eq!(k.nested_sockets.get(&0xa0000001), Some(&829));
            let b = candidate(&db, &k, &doc, &a, &a, None, nested_peer)
                .unwrap()
                .unwrap();
            assert_eq!(b.rollback, a);
            assert_eq!(b.installed.legacy_primary().unwrap().0, "awg1");
            assert!(b.installed.killswitch);
            assert!(b
                .installed
                .full_endpoints
                .as_ref()
                .unwrap()
                .contains(&"198.51.100.41".parse().unwrap()));
            assert_eq!(b.installed.mss.get("awg1"), Some(&1320));
            for family in [Family::V4, Family::V6] {
                let objects = super::super::inventory::objects(&b.installed);
                assert!(
                    objects.contains(&super::super::inventory::Object::FullGuard(
                        super::super::full::Guard::Fence(family)
                    ))
                );
            }

            doc["active_id"] = json!("a");
            let resumed = candidate(&db, &k, &doc, &b.installed, &b.installed, None, nested_peer)
                .unwrap()
                .unwrap();
            assert_eq!(resumed.installed.legacy_primary().unwrap().0, "awg0");
            assert_eq!(resumed.rollback, b.installed);
        }
    }

    #[test]
    fn watchdog_rejects_wrong_nested_path_or_unproven_outer_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(tmp.path()).unwrap();
        let (doc, a) = nested_fixture("permanent");
        for router in [
            NestedRouter {
                outer: "awg3",
                prohibit: true,
            },
            NestedRouter {
                outer: "awg2",
                prohibit: false,
            },
        ] {
            let k = super::super::kernel(&router);
            assert!(candidate(&db, &k, &doc, &a, &a, None, nested_peer)
                .unwrap()
                .is_none());
        }
        let router = NestedRouter {
            outer: "awg2",
            prohibit: true,
        };
        let k = super::super::kernel(&router);
        let wrong_coverage = |cfg: &Value, iface: &str| {
            let mut live = nested_peer(cfg, iface)?;
            if iface == "awg2" {
                live.allowed = vec!["203.0.113.42/32".into()];
            }
            Ok(live)
        };
        assert!(candidate(&db, &k, &doc, &a, &a, None, wrong_coverage)
            .unwrap()
            .is_none());
        let stale_outer = |cfg: &Value, iface: &str| {
            if iface == "awg2" {
                return Err(io::ErrorKind::NotConnected.into());
            }
            nested_peer(cfg, iface)
        };
        assert!(candidate(&db, &k, &doc, &a, &a, None, stale_outer)
            .unwrap()
            .is_none());
    }

    #[test]
    fn reading_a_nested_peer_for_dns_revalidates_transport_without_changing_the_ipv6_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(tmp.path()).unwrap();
        let (doc, a) = nested_fixture("automatic");
        let router = NestedRouter {
            outer: "awg2",
            prohibit: true,
        };
        let k = super::super::kernel(&router);
        let peer_without_ipv6 = |cfg: &Value, iface: &str| {
            let mut live = nested_peer(cfg, iface)?;
            live.ipv6_reachable = false;
            Ok(live)
        };
        let b = candidate(&db, &k, &doc, &a, &a, None, peer_without_ipv6)
            .unwrap()
            .unwrap()
            .installed;
        assert!(matches!(
            b.legacy_full,
            Some(plan::LegacyFull::ForwardReject { .. })
        ));
        let learning = resolve_legacy_transport(
            &doc,
            b.clone(),
            Some(&b),
            Verification::Read(&k),
            nested_peer,
        )
        .unwrap();
        assert!(learning.plan.fully_live());
        assert_eq!(learning.plan.legacy_full, b.legacy_full);
        assert!(!learning.plan.prefixes.contains_key(&Family::V6.any()));

        let failed = resolve_legacy_transport(
            &doc,
            b.clone(),
            Some(&b),
            Verification::Read(&k),
            |cfg, iface| {
                if iface == "awg2" {
                    return Err(io::ErrorKind::NotConnected.into());
                }
                nested_peer(cfg, iface)
            },
        )
        .unwrap();
        assert!(!failed.plan.fully_live());
        assert_eq!(failed.plan.legacy_full, b.legacy_full);
    }

    #[test]
    fn alternate_uses_deployed_identity_and_can_return_to_confirmed_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(dir.path()).unwrap();
        let k = super::super::kernel(&Router);
        let (mut doc, a) = fixture();
        let refused = candidate(&db, &k, &doc, &a, &a, None, |c, i| {
            let mut peer = live(c, i)?;
            if i == "awg1" {
                peer.allowed = vec!["203.0.113.0/24".into()];
            }
            Ok(peer)
        })
        .unwrap();
        assert!(refused.is_none());

        let b = candidate(&db, &k, &doc, &a, &a, None, live)
            .unwrap()
            .unwrap();
        assert_eq!(b.rollback, a);
        assert!(is_transient(&a, &b.installed));
        assert_eq!(b.installed.legacy_primary().unwrap().0, "awg1");
        assert_eq!(
            b.installed.legacy_full,
            Some(plan::LegacyFull::ForwardReject {
                wan: "eth0".into(),
                ipv6_endpoint: false
            })
        );
        assert_eq!(b.installed.full_endpoints.as_ref().unwrap().len(), 2);

        doc["active_id"] = json!("c");
        let stay = candidate(&db, &k, &doc, &a, &b.installed, None, live)
            .unwrap()
            .unwrap();
        assert_eq!(stay.installed, b.installed);

        doc["active_id"] = json!("b");
        let fallback = candidate(&db, &k, &doc, &a, &b.installed, None, |c, i| {
            if i == "awg1" {
                return Err(err("пир изменился"));
            }
            live(c, i)
        })
        .unwrap()
        .unwrap();
        assert_eq!(fallback.installed, a);
        assert!(!fallback.rollback.fully_live());
        assert!(fallback
            .rollback
            .flows()
            .all(|(s, i)| fallback.rollback.effective(s, i).is_none()));
    }
}
