use nfqws2_awg_rules::{kernel::handoff, observed::Policy, Routing};
use nfqws2_router_command::System;
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

pub(super) fn api(port: handoff::PanelEndpoint, method: &str, path: &str) -> io::Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    let runner = System;
    #[cfg(not(target_os = "linux"))]
    let runner = LocalCurl;
    port.api(&runner, method, path).map(String::into_bytes)
}

// Desktop builds also support the local service receipt on loopback.
#[cfg(not(target_os = "linux"))]
struct LocalCurl;
#[cfg(not(target_os = "linux"))]
impl nfqws2_router_command::Runner for LocalCurl {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        if program != "curl" {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let output = std::process::Command::new(program).args(args).output()?;
        if !output.status.success() {
            return Err(io::Error::other("локальный API маршрутизации не ответил"));
        }
        String::from_utf8(output.stdout).map_err(io::Error::other)
    }
}
#[derive(Deserialize)]
struct Snapshot {
    servers: Vec<Server>,
    routing_state: State,
}
#[derive(Deserialize)]
struct Server {
    id: String,
    connected: bool,
    #[serde(default)]
    failover: Option<FailoverState>,
}
#[derive(Deserialize)]
struct FailoverState {
    #[serde(default)]
    double_tunnel_active: bool,
}
#[derive(Deserialize)]
struct State {
    ready: bool,
    #[serde(default)]
    active: bool,
    #[serde(default)]
    pending_commit: bool,
    #[serde(default)]
    revision: u64,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Clients {
    connected: BTreeSet<String>,
    nested: BTreeSet<String>,
}

impl Clients {
    fn read(snapshot: &Snapshot) -> Self {
        let active = |server: &&Server| {
            server
                .failover
                .as_ref()
                .is_some_and(|state| state.double_tunnel_active)
        };
        Self {
            connected: snapshot
                .servers
                .iter()
                .filter(|server| server.connected)
                .map(|server| server.id.clone())
                .collect(),
            nested: snapshot
                .servers
                .iter()
                .filter(active)
                .map(|server| server.id.clone())
                .collect(),
        }
    }

    fn confirm(&self, state: &Snapshot, verified_nested: &BTreeSet<String>) -> io::Result<()> {
        let mut found = Self::read(state);
        found.nested.extend(verified_nested.iter().cloned());
        found.connected.extend(verified_nested.iter().cloned());
        if found.nested != self.nested {
            return Err(io::Error::other(
                "изменился состав действующих вложенных AWG-туннелей",
            ));
        }
        if found.connected != self.connected {
            return Err(io::Error::other(
                "состав подключённых AWG-клиентов отличается от работающей панели Go",
            ));
        }
        Ok(())
    }
}

fn runtime() -> nfqws2_awg_profile::runtime::Runtime {
    nfqws2_awg_profile::runtime::Runtime::new(std::path::Path::new("/"), Default::default())
}

pub(super) fn prepare_clients_only(
    db: &Store,
    port: handoff::PanelEndpoint,
) -> io::Result<Option<Clients>> {
    let doc = nfqws2_awg_profile::read(db)?;
    if !doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|row| row["config"]["enabled"] == true && row["config"]["client"]["enabled"] == true)
    {
        return Ok(None);
    }
    let state = snapshot(port)?;
    if state.routing_state.active || state.routing_state.pending_commit {
        return Err(io::Error::other(
            "состояние маршрутизации изменилось во время подготовки перехода",
        ));
    }
    let clients = Clients::read(&state);
    if clients.connected.is_empty() && clients.nested.is_empty() {
        return Ok(None);
    }
    if !clients.nested.is_subset(&clients.connected) {
        return Err(io::Error::other(
            "не подтверждены работающие вложенные клиенты Go",
        ));
    }
    let direct = clients
        .connected
        .difference(&clients.nested)
        .cloned()
        .collect();
    nfqws2_awg_profile::runtime::Runtime::stage_go_clients_only(db, &direct, &clients.nested)?;
    let next = snapshot(port)?;
    if next.routing_state.active
        || next.routing_state.pending_commit
        || Clients::read(&next) != clients
    {
        return Err(io::Error::other(
            "подключения Go изменились во время подготовки перехода",
        ));
    }
    Ok(Some(clients))
}

pub(super) fn finish_clients_only(
    db: &Store,
    port: handoff::PanelEndpoint,
    expected: &Clients,
) -> io::Result<()> {
    let state = snapshot(port)?;
    if state.routing_state.active || state.routing_state.pending_commit {
        return Err(io::Error::other(
            "маршрутизация неожиданно включилась при переносе клиентов",
        ));
    }
    runtime().verify_go_clients_only(db, &expected.connected, &expected.nested)?;
    expected.confirm(&state, &expected.nested)?;
    nfqws2_awg_profile::runtime::Runtime::confirm_go_clients(db)
}

fn snapshot(port: handoff::PanelEndpoint) -> io::Result<Snapshot> {
    serde_json::from_slice(&api(port, "GET", "awg2")?).map_err(io::Error::other)
}
#[derive(Deserialize)]
struct History {
    rules: Vec<HistoryRule>,
}
#[derive(Deserialize)]
struct HistoryRule {
    rule_index: usize,
    rule_key: String,
    entries: Vec<HistoryEntry>,
}
#[derive(Deserialize)]
struct HistoryEntry {
    domain: String,
    source: String,
    last_seen: u64,
}

fn witnessed_names(
    data: &[u8],
    policy: &Routing,
    matched: &Policy,
    clients: &[IpAddr],
) -> io::Result<Vec<String>> {
    let history: History = serde_json::from_slice(data).map_err(io::Error::other)?;
    let mut names = Vec::new();
    for rule in history.rules {
        let Some(zone) = policy.zones.get(rule.rule_index) else {
            continue;
        };
        if !zone.enabled || rule.rule_key != nfqws2_awg_rules::discoveries::rule_key(zone)? {
            continue;
        }
        for entry in rule.entries {
            let name = entry.domain;
            if entry.source == "dns"
                && entry.last_seen != 0
                && nfqws2_awg_profile::exact_route_hostname(&name) == Some(name.as_str())
                && clients.iter().any(|src| {
                    matched.matched(&name, Some(*src)) == Some(rule.rule_index)
                        || matched
                            .legacy_dns_zones(&name, Some(*src))
                            .contains(&rule.rule_index)
                })
            {
                names.push((std::cmp::Reverse(entry.last_seen), name));
            }
        }
    }
    names.sort_unstable();
    Ok(names.into_iter().map(|(_, name)| name).take(64).collect())
}

fn dns_path(
    db: &Store,
    policy: &Routing,
    port: handoff::PanelEndpoint,
    legacy: bool,
) -> io::Result<()> {
    let matched = if legacy {
        Policy::compile_legacy_full(policy)?
    } else {
        Policy::compile(policy)?
    };
    let clients = handoff::dns_clients(&System, policy)?;
    let addresses: Vec<_> = clients.iter().map(|c| c.address).collect();
    let tunnel = !legacy
        && policy.zones.iter().any(|z| {
            z.enabled
                && !z.waiting_for_connection
                && z.direction() == "tunnel"
                && z.domains
                    .iter()
                    .any(|d| d != "*" && d.parse::<IpAddr>().is_err() && !d.contains('/'))
        });
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 5354));
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut names = BTreeSet::new();
    let mut exact = policy
        .zones
        .iter()
        .filter(|z| {
            z.enabled
                && !z.waiting_for_connection
                && (!legacy || !z.source_ips.is_empty())
                && (!tunnel || z.direction() == "tunnel")
        })
        .flat_map(|z| &z.domains)
        .filter_map(|v| nfqws2_awg_profile::exact_route_hostname(v));
    // Wildcard zones can be checked with a name seen by the previous resolver.
    // The history supplies only the name. Both DNS replies and their current
    // kernel destination still have to pass the same live checks.
    let observed = api(port, "GET", "awg2/routing/discovered")
        .and_then(|data| witnessed_names(&data, policy, &matched, &addresses))
        .unwrap_or_default();
    let mut observed = observed.iter().map(String::as_str);
    let first = [exact.next(), observed.next()];
    for name in first.into_iter().flatten().chain(exact).chain(observed) {
        if Instant::now() >= deadline {
            break;
        }
        if !names.insert(name) {
            continue;
        }
        let mut probes = Vec::new();
        for c in &clients {
            if legacy {
                probes.extend(
                    matched
                        .legacy_dns_zones(name, Some(c.address))
                        .into_iter()
                        .map(|i| (c, i)),
                );
            } else if let Some(i) = matched.matched(name, Some(c.address)) {
                if !tunnel || policy.zones[i].direction() == "tunnel" {
                    probes.push((c, i));
                }
            }
        }
        if probes.is_empty() {
            continue;
        }
        let request = nfqws2_dns::build_query(name, 1, nfqws2_dns::transaction_id()?)?;
        let mut passed = true;
        for exchange in [nfqws2_dns::exchange_until, nfqws2_dns::exchange_tcp_until] {
            let result = exchange(
                &request,
                addr,
                deadline.min(Instant::now() + Duration::from_secs(4)),
            )
            .and_then(|raw| nfqws2_dns::route_answer(&raw))
            .ok()
            .flatten();
            if let Some(r) = result {
                probes.retain(|(client, index)| {
                    r.addresses.iter().any(|&ip| {
                        Instant::now() < deadline
                            && handoff::check_destination(db, &System, ip, *index, client).is_ok()
                    })
                });
            } else {
                probes.clear();
            }
            if probes.is_empty() {
                passed = false;
                break;
            }
        }
        if passed {
            return Ok(());
        }
    }
    Err(io::Error::other(
        "не удалось подтвердить ответы DNS по UDP/TCP и путь проверяемой зоны",
    ))
}

fn acceptable_routing_state(
    state: &State,
    parked: impl FnOnce() -> io::Result<Option<handoff::ParkedTrialStatus>>,
) -> io::Result<bool> {
    if state.ready && state.active {
        return Ok(true);
    }
    Ok(parked()?
        == Some(handoff::ParkedTrialStatus {
            revision: state.revision,
            pending_commit: state.pending_commit,
        }))
}

pub(super) fn finish(db: &Store, port: handoff::PanelEndpoint) -> io::Result<()> {
    let accepted = |state: &State| {
        acceptable_routing_state(state, || handoff::parked_trial_status(db, &System))
    };
    let deadline = Instant::now() + Duration::from_secs(50);
    let state = loop {
        if let Ok(s) = snapshot(port) {
            if accepted(&s.routing_state).unwrap_or(false) {
                break s;
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "Rust не установил проверяемую политику AWG",
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let check = handoff::check_trial(db, &System)?;
    let runtime = runtime();
    runtime.verify_go_nested_trial(db, &check.nested)?;
    let clients = Clients {
        connected: check.connected,
        nested: check.nested,
    };
    if check.parked {
        if !Clients::read(&state).nested.is_empty() {
            return Err(io::Error::other(
                "во время остановленного переноса появился вложенный AWG-туннель",
            ));
        }
    } else {
        clients.confirm(&state, &clients.nested)?;
    }
    if check.redirects_dns {
        dns_path(db, &check.policy, port, check.legacy_scoped_dns)?;
    }
    if state.routing_state.pending_commit {
        let committed: serde_json::Value =
            serde_json::from_slice(&api(port, "POST", "awg2/routing/commit")?)?;
        if committed["status"] != "committed" {
            return Err(io::Error::other("неожиданный ответ подтверждения AWG"));
        }
    }
    let state = snapshot(port)?.routing_state;
    if state.pending_commit || !accepted(&state)? {
        return Err(io::Error::other(
            "маршрутизация не подтвердилась после проверки",
        ));
    }
    runtime.verify_go_nested_trial(db, &clients.nested)?;
    handoff::finished(db)?;
    nfqws2_awg_profile::runtime::Runtime::confirm_go_clients(db)?;
    println!("committed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parked_installer_readiness_requires_exact_revision_and_commit_phase() {
        let mut state: State = serde_json::from_value(json!({
            "ready": false, "active": false, "pending_commit": true, "revision": 8
        }))
        .unwrap();
        let proof = handoff::ParkedTrialStatus {
            revision: 8,
            pending_commit: true,
        };
        assert!(acceptable_routing_state(&state, || Ok(Some(proof))).unwrap());
        state.pending_commit = false;
        assert!(!acceptable_routing_state(&state, || Ok(Some(proof))).unwrap());
        state.pending_commit = true;
        state.revision = 9;
        assert!(!acceptable_routing_state(&state, || Ok(Some(proof))).unwrap());
        assert!(!acceptable_routing_state(&state, || Ok(None)).unwrap());
        state.ready = true;
        state.active = true;
        assert!(acceptable_routing_state(&state, || panic!("existing live path")).unwrap());
    }

    #[test]
    fn client_only_upgrade_checks_saved_connections_without_requiring_active_routes() {
        let source = json!({
            "routing_state": {"ready":false,"active":false},
            "servers":[
                {"id":"outer","connected":true},
                {"id":"inner","connected":true,"failover":{"double_tunnel_active":true}},
                {"id":"disabled","connected":false}
            ]
        });
        let original: Snapshot = serde_json::from_value(source.clone()).unwrap();
        let expected = Clients::read(&original);
        let mut updated = source.clone();
        updated["servers"][1]["connected"] = false.into();
        updated["servers"][1]["failover"]["double_tunnel_active"] = false.into();
        let observation = |data: &serde_json::Value| serde_json::from_value(data.clone()).unwrap();
        assert!(expected
            .confirm(&observation(&updated), &BTreeSet::new())
            .is_err());
        expected
            .confirm(&observation(&updated), &expected.nested)
            .unwrap();
        updated["servers"][0]["connected"] = false.into();
        assert!(expected
            .confirm(&observation(&updated), &expected.nested)
            .is_err());
        updated["servers"][0]["connected"] = true.into();
        updated["servers"][2]["connected"] = true.into();
        assert!(expected
            .confirm(&observation(&updated), &expected.nested)
            .is_err());
    }

    #[test]
    fn dns_probes_only_use_witnesses_of_the_current_tunnel_rule() {
        let policy: Routing = serde_json::from_value(json!({"mode":"zones","zones":[
            {"enabled":true,"route":"direct","domains":["no.example.test"]},
            {"enabled":true,"route":"tunnel","domains":["*.example.test"],"tunnel_id":"awg0"}
        ]}))
        .unwrap();
        let matched = Policy::compile(&policy).unwrap();
        let key = nfqws2_awg_rules::discoveries::rule_key(&policy.zones[1]).unwrap();
        let entries = json!([
            {"domain":"ok.example.test","source":"dns","last_seen":2},
            {"domain":"no.example.test","source":"dns","last_seen":3},
            {"domain":"outside.test","source":"dns","last_seen":3},
            {"domain":"sni.example.test","source":"sni","last_seen":3}
        ]);
        for (rule_key, expected) in [(key.as_str(), vec!["ok.example.test"]), ("old", vec![])] {
            let data = serde_json::to_vec(
                &json!({"rules":[{"rule_index":1,"rule_key":rule_key,"entries":entries}]}),
            )
            .unwrap();
            assert_eq!(
                witnessed_names(&data, &policy, &matched, &[Ipv4Addr::LOCALHOST.into()]).unwrap(),
                expected
            );
        }
    }
}
