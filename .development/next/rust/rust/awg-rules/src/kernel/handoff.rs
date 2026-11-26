//! Capture a working legacy installation before its orderly shutdown.
//! A saved Go "active" bit alone is also true during its rollback window.
use super::{learning::Member, plan, DnsSnapshot, Journal, LivePeer, Plan, Prefix};
use crate::{discoveries::rule_key, identity, model::err, policy, Routing, Zone};
use nfqws2_router_command::Runner;
use nfqws2_store::{Store, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io,
    net::IpAddr,
    time::{Duration, Instant},
};
pub(super) mod implicit_multi;
mod legacy;
mod panel;
#[cfg(test)]
pub(super) use legacy::tests::Go as LegacyTestRouter;
pub use panel::{listen_address, PanelEndpoint};
pub(super) mod nft_trial;
mod ordered;
pub(super) mod parked_guard;
mod parked_multi;

const FILE: &str = "awg-go-handoff.json";
const CHECK: &str = "awg-go-trial-check.json";
const RELEASE: &str = "awg-go-release.json";
const MAX_SIZE: u64 = 32 << 20;
const MAX_AGE: u64 = 180;
const OLD_TRIAL: Duration = Duration::from_secs(91);

/// Installer dependency selection only. Authorization to migrate requires the
/// separate live preflight and is never granted by this saved setting.
pub fn needs_ip(db: &Store) -> io::Result<bool> {
    let doc = nfqws2_awg_profile::read(db)?;
    if !Journal::read(db)?.idle() {
        return Ok(false);
    }
    let nested_clients = doc["servers"].as_array().into_iter().flatten().any(|row| {
        let cfg = &row["config"];
        cfg["enabled"] == true
            && cfg["client"]["enabled"] == true
            && cfg["client"]["double_tunnel_id"]
                .as_str()
                .is_some_and(|outer| !outer.is_empty())
    });
    Ok(policy::current(&doc)?.active || nested_clients)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    created: u64,
    boot: String,
    policy_hash: String,
    #[serde(deserialize_with = "super::journal::route_rows")]
    warm: Vec<Member>,
    #[serde(default)]
    legacy_full: Option<plan::LegacyFull>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    implicit_multi_carrier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    implicit_multi_parked: Option<parked_multi::Parked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    go_multi_v6_reject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_scope: Option<super::legacy_scope::Scope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    legacy_dns_bridges: Vec<String>,
    connected: BTreeSet<String>,
    #[serde(default)]
    nested: BTreeSet<String>,
}
#[derive(Serialize, Deserialize)]
struct Check {
    boot: String,
    created: u64,
    hash: String,
    connected: BTreeSet<String>,
    #[serde(default)]
    nested: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    implicit_multi_parked: Option<parked_multi::Parked>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    boot: String,
    checkpoint: Option<Journal>,
}
/// Called only by the installer bracketing an orderly Rust shutdown. Keep the
/// pre-stop witness and the last write-ahead journal until the directory swap.
pub fn release_go_routing(db: &Store, run: &dyn Runner, checkpoint: bool) -> io::Result<()> {
    db.transaction(|tx| {
        let k = super::kernel(run);
        let mut proof: Release = db.read_runtime(RELEASE, super::RECEIPT_LIMIT + 4096)?;
        if proof.boot != super::boot_id(&k)? {
            return Err(err("свидетельство обновления относится к другой загрузке"));
        }
        let current = Journal::read(db)?;
        if !current.boot.is_empty() && current.boot != proof.boot {
            return Err(err("журнал маршрутов относится к другой загрузке"));
        }
        if checkpoint {
            if proof.checkpoint.is_none() {
                let mut before = current;
                // No Rust policy has been attempted if the native journal is
                // absent. Still bind this empty pre-stop witness to the boot.
                before.boot = proof.boot.clone();
                proof.checkpoint = Some(before);
                tx.save_runtime_bounded(RELEASE, &proof, super::RECEIPT_LIMIT + 4096)?;
            }
            return Ok(());
        }
        let before = proof
            .checkpoint
            .ok_or_else(|| err("нет снимка владения Rust перед остановкой"))?
            .validated()?;
        if before.boot != proof.boot {
            return Err(err("повреждён снимок владения перед остановкой"));
        }
        let armed = parked_guard::Armed::read(db)?;
        let protected = if let Some(armed) = &armed {
            let doc = nfqws2_awg_profile::read(db)?;
            armed.verify_native(db, &k, &doc)?;
            super::objects(&armed.plan)
        } else {
            BTreeSet::new()
        };
        let mut current_claims = current.claims();
        current_claims.extend(protected.iter().cloned());
        let prior = if before == current {
            None
        } else {
            Some(before.claims())
        };
        drop(before);
        drop(current);
        let mut combined;
        let claims = if let Some(old) = prior.filter(|s| !s.is_subset(&current_claims)) {
            combined = old;
            for object in &current_claims {
                if !combined.contains(object) {
                    combined.insert(object.clone());
                }
            }
            &combined
        } else {
            &current_claims
        };
        let present = k.inventory_for(claims, &protected, true)?;
        // A successful Suspend may have already relinquished ownership. An
        // identical object that has since reappeared cannot be deleted safely.
        if !present.is_subset(&current_claims) {
            return Err(err(
                "ранее снятый объект маршрутизации появился снова, сохранён для проверки",
            ));
        }
        super::synchronize(&k, &present, &protected)?;
        if k.inventory_for(claims, &protected, true)? != protected {
            return Err(err("ядро не подтвердило состав оставшейся защиты при откате"));
        }
        super::acceleration::restore(db, tx, &k)?;
        super::acceleration::verify_released(&k)?;
        tx.save_runtime_bounded(
            super::RECEIPT,
            &Journal {
                boot: proof.boot,
                ..Default::default()
            },
            super::RECEIPT_LIMIT,
        )
    })
}

pub fn arm_parked_guard(db: &Store, run: &dyn Runner, port: PanelEndpoint) -> io::Result<bool> {
    parked_guard::arm(db, run, port)
}

pub fn release_parked_guard(db: &Store, run: &dyn Runner, port: PanelEndpoint) -> io::Result<()> {
    parked_guard::release(db, run, port)
}

pub fn finish_parked_guard(db: &Store, run: &dyn Runner) -> io::Result<()> {
    parked_guard::finish(db, run)
}
#[derive(Deserialize)]
struct Readiness {
    ready: bool,
    applying: bool,
    revision: u64,
}
#[derive(Deserialize)]
struct Live {
    routing_config: Routing,
    routing_rules: Vec<Zone>,
    routing_state: Readiness,
    servers: Vec<Server>,
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
fn hash(db: &Store, doc: &Value, config: &Routing) -> io::Result<String> {
    let refs = identity::refs(doc, &identity::live(doc))?;
    let mut policy = policy::policy_hash(config, &refs);
    if let Some(zone) = implicit_multi::zone(doc, config) {
        let mut effective = config.clone();
        effective.zones.push(zone);
        policy.push_str(&policy::policy_hash(&effective, &refs));
    }
    if config.zones.iter().any(|z| {
        z.enabled
            && z.domains
                .iter()
                .any(|s| crate::model::dependency(s).is_some())
    }) {
        let effective = crate::sources::expand(db, config.clone())?;
        policy.push_str(&policy::policy_hash(&effective, &refs));
    }
    if config.mode == "full" {
        // A scoped Go set uses the original selected profile's zone order,
        // which can differ from the shared multi-policy's flattened order.
        if let Some(owner) = crate::model::selected_profile(doc) {
            let raw = crate::policy::decode(&owner["config"]["routing"])?;
            if raw.zones.iter().any(|z| {
                z.enabled
                    && !z.waiting_for_connection
                    && !z.source_ips.is_empty()
                    && !z.domains.is_empty()
            }) {
                policy.push_str(&policy::policy_hash(
                    &super::learning::legacy_policy(db, doc)?,
                    &refs,
                ));
            }
        }
    }
    // A connection-level reserve or transport can change the egress even if
    // the zones and configured public keys in the routing document are equal.
    let clients: Vec<_> = doc["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let c = &r["config"]["client"];
            let wire = if r["applied_config"].is_object() {
                &r["applied_config"]
            } else {
                &r["config"]
            };
            (
                &r["id"],
                &r["config"]["enabled"],
                (
                    &wire["public_key"],
                    &wire["client_iface"],
                    &wire["endpoint"],
                    &wire["mtu"],
                ),
                &c["enabled"],
                &c["peer_id"],
                &c["standby"],
                &c["fallback_tunnel_ids"],
                &c["double_tunnel_id"],
                &c["double_tunnel_mode"],
                &c["endpoint_backups"],
            )
        })
        .collect();
    Ok(identity::digest(
        &serde_json::to_vec(&(policy, clients, &doc["active_id"]))?,
        32,
    ))
}
fn call(run: &dyn Runner, program: &str, args: &[&str]) -> io::Result<String> {
    run.run(program, args, Instant::now() + Duration::from_secs(8))
}
#[derive(PartialEq, Eq)]
struct Witness {
    revision: u64,
    pid: u32,
    process: String,
    connected: BTreeSet<String>,
    nested: BTreeSet<String>,
}
/// Go's tunnel goto ends in ACCEPT. Direct and unmatched packets return
/// without modifying any selector or mark, so adjacent copies of the same
/// hook produce exactly the same classification.
fn go_jumps(rows: &[Vec<&str>], parent: &str, target: &str, first: bool) -> bool {
    let mut seen = false;
    let mut after = false;
    for (i, w) in rows
        .iter()
        .filter(|r| r.starts_with(&["-A", parent]))
        .enumerate()
    {
        if w.as_slice() == ["-A", parent, "-j", target] {
            if after || first && !seen && i != 0 {
                return false;
            }
            seen = true;
        } else {
            if w.windows(2)
                .any(|p| matches!(p[0], "-j" | "-g") && p[1].starts_with("AWG2_"))
            {
                return false;
            }
            if seen
                && !(parent == "PREROUTING"
                    && w.as_slice()
                        == [
                            "-A",
                            parent,
                            "-m",
                            "connmark",
                            "--mark",
                            "0x8000d500/0x8000ffff",
                            "-j",
                            "N2S_DNS_PRE",
                        ]
                    && dns_pre_terminal(rows))
            {
                after = true;
            }
        }
    }
    seen
}
/// Go dnsroute's private marked-socket chain either queues the reply or
/// accepts it in mangle. Neither verdict returns to the next iptables rule.
pub(super) fn dns_pre_terminal(rows: &[Vec<&str>]) -> bool {
    let mut rules = rows
        .iter()
        .filter(|r| r.starts_with(&["-A", "N2S_DNS_PRE"]))
        .map(|r| &r[2..]);
    if rules.next()
        != Some(
            [
                "-m",
                "mark",
                "--mark",
                "0x40000000/0x40000000",
                "-j",
                "ACCEPT",
            ]
            .as_slice(),
        )
    {
        return false;
    }
    let Some(
        ["-p", "tcp", "-m", "connbytes", params @ .., "-j", "NFQUEUE", "--queue-num", n, "--queue-bypass"],
    ) = rules.next()
    else {
        return false;
    };
    let pairs = params.chunks_exact(2).collect::<BTreeSet<_>>();
    n.parse::<u16>().is_ok()
        && params.len() == 6
        && pairs.contains(["--connbytes", "1:32"].as_slice())
        && pairs.contains(["--connbytes-mode", "packets"].as_slice())
        && pairs.contains(["--connbytes-dir", "reply"].as_slice())
        && rules.next() == Some(["-j", "ACCEPT"].as_slice())
        && rules.next().is_none()
}
fn live_chain(run: &dyn Runner, single: bool) -> io::Result<&'static str> {
    let expected = if single { "AWG2_MARK" } else { "AWG2_MULTI" };
    let mut jumps = call(run, "iptables", &["-t", "mangle", "-S", "PREROUTING"])?;
    if jumps.lines().filter(|l| l.ends_with(expected)).count() > 1 && jumps.contains("N2S_DNS_PRE")
    {
        jumps.push('\n');
        jumps.push_str(&call(
            run,
            "iptables",
            &["-t", "mangle", "-S", "N2S_DNS_PRE"],
        )?);
    }
    let hooks = jumps
        .lines()
        .map(|l| l.split_ascii_whitespace().collect())
        .collect::<Vec<Vec<_>>>();
    if !go_jumps(&hooks, "PREROUTING", expected, false) {
        return Err(err(
            "действующая цепочка Go не соответствует сохранённой политике AWG",
        ));
    }
    Ok(expected)
}
pub fn source_chain(db: &Store, run: &dyn Runner) -> io::Result<&'static str> {
    let doc = nfqws2_awg_profile::read(db)?;
    let policy = policy::current(&doc)?;
    if let Some(zone) = implicit_multi::zone(&doc, &policy) {
        if !Journal::read(db)?.idle() || doc["rust_static_routing"].is_object() {
            return Err(err("сохранён действующий собственный журнал Rust"));
        }
        implicit_multi::source_ipv6(&super::kernel(run), &doc, &zone)?;
        return live_chain(run, false);
    }
    live_chain(run, legacy::standalone(&policy, &doc))
}
fn live(
    run: &dyn Runner,
    endpoint: PanelEndpoint,
    wanted: &Routing,
    single: bool,
) -> io::Result<Witness> {
    // Neither the legacy generation nor a PID alone survives a process
    // restart unambiguously. Pair both with the kernel process start time.
    let pid = call(run, "cat", &["/opt/var/run/nfqws2-strategy.pid"])?;
    let pid = pid
        .trim()
        .parse::<u32>()
        .map_err(|_| err("неверный PID прежней панели"))?;
    let stat = call(run, "cat", &[&format!("/proc/{pid}/stat")])?;
    let ticks = stat
        .rsplit_once(')')
        .and_then(|(_, s)| s.split_ascii_whitespace().nth(19))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| err("не удалось определить работающий процесс Go"))?;
    let data = endpoint
        .api(run, "GET", "awg2")
        .map_err(|_| err("локальный API работающей Go-панели недоступен"))?;
    let mut live: Live = serde_json::from_str(&data)
        .map_err(|_| err("прежняя панель не вернула состояние маршрутизации Go"))?;
    live.routing_config.zones = live.routing_rules;
    live.routing_config.normalize();
    if !live.routing_state.ready
        || live.routing_state.applying
        || !live.routing_config.active
        || live.routing_config.mode != wanted.mode
        || live.routing_config.domain_source != wanted.domain_source
        || live.routing_config.mtu != wanted.mtu
        || live.routing_config.killswitch != wanted.killswitch
        || live.routing_config.sni_routing != wanted.sni_routing
        || live.routing_config.trace_enabled != wanted.trace_enabled
        || live.routing_config.zones.len() != wanted.zones.len()
    {
        return Err(err(
            "исходная политика маршрутизации не готова к обновлению",
        ));
    }
    for (left, right) in live.routing_config.zones.iter().zip(&wanted.zones) {
        if left.enabled != right.enabled || rule_key(left)? != rule_key(right)? {
            return Err(err(
                "порядок или состав зон действующей панели отличается от сохранённого",
            ));
        }
    }
    live_chain(run, single)?;
    Ok(Witness {
        revision: live.routing_state.revision,
        pid,
        process: format!("{pid}/{ticks}"),
        nested: live
            .servers
            .iter()
            .filter(|s| s.failover.as_ref().is_some_and(|f| f.double_tunnel_active))
            .map(|s| s.id.clone())
            .collect(),
        connected: live
            .servers
            .into_iter()
            .filter(|s| s.connected)
            .map(|s| s.id)
            .collect(),
    })
}

pub(super) fn go_dns_redirect(line: &str) -> Option<(&str, &str)> {
    let words: Vec<_> = line.split_ascii_whitespace().collect();
    let (bridge, proto) = match words.as_slice() {
        ["-A", "PREROUTING", "-i", br, "-p", proto, "-m", module, "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
            if proto == module =>
        {
            (*br, *proto)
        }
        ["-A", "PREROUTING", "-i", br, "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"] => {
            (*br, *proto)
        }
        _ => return None,
    };
    (super::valid_dns_bridge(bridge) && matches!(proto, "udp" | "tcp")).then_some((bridge, proto))
}

pub(super) fn member_expiry(options: &[&str], now: u64) -> io::Result<u64> {
    let invalid = || err("неизвестные параметры записи IP-набора Go");
    let (until, counters) = match options {
        ["timeout", seconds, rest @ ..] => {
            let seconds = seconds.parse::<u32>().map_err(|_| invalid())?;
            let until = if seconds == 0 {
                u64::MAX
            } else {
                now.saturating_add(u64::from(seconds))
            };
            (until, rest)
        }
        rest => (u64::MAX, rest),
    };
    match counters {
        [] => Ok(until),
        ["packets", packets, "bytes", bytes]
            if packets.parse::<u64>().is_ok() && bytes.parse::<u64>().is_ok() =>
        {
            Ok(until)
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
fn capture_fixture(members: usize, corrupt: bool) -> io::Result<Vec<Member>> {
    use std::fmt::Write;
    struct GoSet {
        members: usize,
        corrupt: bool,
    }
    impl Runner for GoSet {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            match (program, args) {
                ("sh", ["-c", _]) => Ok(String::new()),
                ("iptables", ["-t", "mangle", "-S", "AWG2_MULTI"]) => {
                    Ok("-A AWG2_MULTI -m set --match-set awgm_000 dst -j RETURN".into())
                }
                ("ipset", ["save", "awgm_000"]) => {
                    let mut text = String::from("create awgm_000 hash:net family inet hashsize 1024 maxelem 65536 timeout 600 counters\n");
                    for index in 0..self.members {
                        let address = std::net::Ipv4Addr::from(0x3100_0000 + index as u32 * 7);
                        let lease = if index == 0 { 0 } else { 317 };
                        writeln!(text, "add awgm_000 {address} timeout {lease} packets 18446744073709551615 bytes 18446744073709551615").unwrap();
                    }
                    if self.corrupt {
                        text.push_str("add awgm_000 192.0.2.10/32 nomatch\n");
                    }
                    Ok(text)
                }
                _ => Err(io::ErrorKind::Unsupported.into()),
            }
        }
    }
    let policy: Routing = serde_json::from_value(serde_json::json!({
        "mode":"zones", "domain_source":"dnsproxy",
        "zones":[{"enabled":true,"domains":["*.office.example"]}]
    }))
    .unwrap();
    capture_members(&GoSet { members, corrupt }, &policy, 1000)
}

#[cfg(test)]
#[test]
fn captures_full_go_ipset_with_leases_and_counters() {
    let full = super::packed::ZONE_LIMIT;
    let entries = capture_fixture(full, false).unwrap();
    assert_eq!(entries.len(), full);
    assert_eq!(entries[0].until, u64::MAX);
    assert_eq!(entries[1].until, 1317);
    assert!(capture_fixture(full + 1, false).is_err());
}

#[cfg(test)]
#[test]
fn go_capture_preserves_permanent_and_expiring_entries_with_counters() {
    let entries = capture_fixture(2, false).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!((entries[0].until, entries[1].until), (u64::MAX, 1317));
    assert!(capture_fixture(2, true).is_err());
}

fn capture_members(run: &dyn Runner, routing: &Routing, now: u64) -> io::Result<Vec<Member>> {
    let v6 = call(
        run,
        "sh",
        &[
            "-c",
            r#"
if [ -e /proc/net/ipv6_route ] && [ -e /proc/net/ip6_tables_names ]; then
    [ -r /proc/net/ip6_tables_names ] || exit 1
    if grep -qx mangle /proc/net/ip6_tables_names; then ip6tables -t mangle -S || exit 1; fi
fi"#,
        ],
    )?;
    if v6
        .lines()
        .any(|l| l.contains("AWG2_") || l.contains("awgm_"))
    {
        return Err(err(
            "обнаружена дополнительная IPv6-маршрутизация Go, перенос требует её явной проверки",
        ));
    }
    let chain = call(run, "iptables", &["-t", "mangle", "-S", "AWG2_MULTI"])?;
    let blanket = routing.global_default_zone().is_some();
    let ordered = routing.killswitch
        || routing.zones.iter().any(|z| {
            z.enabled
                && !z.waiting_for_connection
                && (z.only_catch_all() || !z.source_ips.is_empty())
        });
    let names = chain
        .lines()
        .flat_map(|line| {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            words
                .windows(3)
                .filter(|w| w[0] == "--match-set" && w[2] == "dst")
                .map(|w| w[1])
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    let mut warm = Vec::new();
    for (index, zone) in routing
        .zones
        .iter()
        .enumerate()
        .filter(|(_, z)| z.enabled && !z.waiting_for_connection)
    {
        // An unconditional AWG2_MULTI jump has no destination set. Verify
        // its action, RPDB lookup and physical default before saving.
        if zone.only_catch_all() {
            continue;
        }
        let name = format!("awgm_{index:03}");
        if !names.contains(name.as_str()) {
            if zone.ips.iter().chain(&zone.domains).all(|v| {
                v.contains(':') && v.parse::<Prefix>().is_ok() && !crate::model::catch_all(v)
            }) {
                continue;
            }
            return Err(err("отсутствует работающий IP-набор включённой зоны Go"));
        }
        let static_prefixes = zone
            .ips
            .iter()
            .chain(&zone.domains)
            .filter(|s| crate::model::ipish(s) && !crate::model::catch_all(s))
            .map(|s| s.parse::<Prefix>())
            .collect::<io::Result<BTreeSet<_>>>()?;
        let contents = run.run_bounded(
            "ipset",
            &["save", &name],
            Instant::now() + Duration::from_secs(20),
            8 << 20,
        )?;
        let mut header = false;
        let mut exact = BTreeSet::new();
        let mut count = 0;
        for line in contents.lines() {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            match words.as_slice() {
                ["create", set, "hash:net", options @ ..]
                    if *set == name
                        && !header
                        && options.windows(2).any(|p| p == ["family", "inet"]) =>
                {
                    header = true
                }
                ["add", set, value, rest @ ..] if *set == name && header => {
                    count += 1;
                    if count > super::packed::ZONE_LIMIT {
                        return Err(err("IP-набор зоны Go превышает допустимое число адресов"));
                    }
                    let until = member_expiry(rest, now)?;
                    let prefix = value.parse::<Prefix>()?;
                    if prefix.family() != plan::Family::V4 {
                        return Err(err(
                            "семейство адреса не соответствует действующему набору Go",
                        ));
                    }
                    if ordered {
                        exact.insert(prefix);
                    }
                    if prefix.ancestors().any(|p| static_prefixes.contains(&p)) {
                        continue;
                    }
                    let host = value
                        .split('/')
                        .next()
                        .unwrap_or_default()
                        .parse::<IpAddr>()
                        .map_err(|_| err("неверный адрес в IP-наборе Go"))?;
                    if zone.domains.is_empty() && !zone.dns_catch_all()
                        || prefix != Prefix::host(host)
                        || !prefix.safe()
                    {
                        return Err(err(
                            "в наборе Go есть диапазон, которого нет в конфигурации зоны",
                        ));
                    }
                    // Go preserves hash:net members across refreshes while the
                    // policy is unchanged. Keep their remaining lease, including
                    // permanent members, until an administrator reapplies it.
                    if warm.len() >= super::packed::LIMIT {
                        return Err(err(
                            "суммарный снимок зон Go превышает допустимое число адресов",
                        ));
                    }
                    warm.push(Member {
                        zone: index,
                        ip: host,
                        until,
                    });
                }
                _ => return Err(err("неизвестное содержимое действующего IP-набора Go")),
            }
        }
        if !header {
            return Err(err("не удалось прочитать действующий IP-набор Go"));
        }
        if ordered
            && static_prefixes
                .iter()
                .filter(|p| p.family() == plan::Family::V4)
                .any(|p| !exact.contains(p))
        {
            return Err(err("в действующем наборе Go отсутствует настроенная сеть"));
        }
        if blanket
            && exact
                != static_prefixes
                    .iter()
                    .copied()
                    .filter(|p| p.family() == plan::Family::V4)
                    .collect()
        {
            return Err(err(
                "прямые исключения действующего полного туннеля отличаются от сохранённых",
            ));
        }
    }
    warm.sort_unstable_by_key(|row| (row.zone, row.ip));
    Ok(warm)
}

pub(super) fn verify_go_default(
    run: &dyn Runner,
    k: &super::Kernel<'_>,
    plan: &Plan,
    policy: &Routing,
) -> io::Result<()> {
    verify_go_default_mode(run, plan, policy, |entries, action| {
        let iface = go_action(k, entries, action, |i| plan.protected(i))?;
        if plan.flows().next().and_then(|(s, i)| plan.effective(s, i)) == Some(iface.as_str()) {
            Ok(())
        } else {
            Err(err("не подтверждён действующий маршрут по умолчанию Go"))
        }
    })
}

fn verify_go_parked(
    run: &dyn Runner,
    k: &super::Kernel<'_>,
    plan: &Plan,
    policy: &Routing,
    parked: &parked_multi::Parked,
    armed: bool,
) -> io::Result<()> {
    verify_go_default_mode(run, plan, policy, |entries, action| {
        let installed = go_action_route(k, entries, action, Some(parked))?;
        if installed.slot != parked.slot
            || installed.dev.is_some()
            || installed.fence != parked.guarded()
        {
            return Err(err("не подтверждён остановленный маршрут по умолчанию Go"));
        }
        parked.verify_rules(k, armed)?;
        parked.verify_absent(k)
    })
}

fn verify_go_default_mode<T>(
    run: &dyn Runner,
    plan: &Plan,
    policy: &Routing,
    verify: impl FnOnce(&[Vec<&str>], &str) -> io::Result<T>,
) -> io::Result<T> {
    let missing = || err("не подтверждён действующий маршрут по умолчанию Go");
    let rows = call(run, "iptables", &["-t", "mangle", "-S"])?;
    let entries: Vec<Vec<&str>> = rows
        .lines()
        .map(|l| l.split_ascii_whitespace().collect())
        .collect();
    for parent in ["OUTPUT", "PREROUTING"] {
        if !go_jumps(&entries, parent, "AWG2_MULTI", true) {
            return Err(missing());
        }
    }
    let chain: Vec<_> = entries
        .iter()
        .filter(|w| w.starts_with(&["-A", "AWG2_MULTI"]))
        .map(Vec::as_slice)
        .collect();
    let first = chain
        .iter()
        .position(|w| w.contains(&"-g"))
        .ok_or_else(missing)?;
    let (chain, jumps) = chain.split_at(first);
    let mut sources = BTreeSet::new();
    let action = *jumps.first().and_then(|w| w.last()).ok_or_else(missing)?;
    for jump in jumps {
        match *jump {
            ["-A", "AWG2_MULTI", "-g", a] if *a == action && jumps.len() == 1 => (),
            ["-A", "AWG2_MULTI", "-s", src, "-g", a] if *a == action => {
                sources.insert(src.parse::<Prefix>()?);
            }
            _ => return Err(missing()),
        }
    }
    let original_sources = policy
        .global_default_zone()
        .ok_or_else(missing)?
        .source_ips
        .iter()
        .map(|v| v.parse::<Prefix>())
        .collect::<io::Result<BTreeSet<_>>>()?;
    if sources != original_sources {
        return Err(missing());
    }
    let private = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ]
    .map(|v| v.parse::<Prefix>().unwrap());
    let mut expected: BTreeSet<_> = private.into_iter().collect();
    for &ip in plan
        .full_endpoints
        .as_ref()
        .ok_or_else(missing)?
        .iter()
        .filter(|i| i.is_ipv4())
    {
        if !private.iter().any(|p| p.contains(ip)) {
            expected.insert(Prefix::host(ip));
        }
    }
    let mut returns = BTreeSet::new();
    let mut probe = false;
    let mut sets = BTreeSet::new();
    for &w in chain {
        match w {
            ["-A", "AWG2_MULTI", "-d", dest, "-j", "RETURN"] => {
                returns.insert(dest.parse::<Prefix>()?);
            }
            ["-A", "AWG2_MULTI", "-m", "mark", "--mark", "0x20000000/0x20000000", "-j", "RETURN"] => {
                probe = true
            }
            ["-A", "AWG2_MULTI", "-m", "set", "--match-set", name, "dst", "-j", "RETURN"] => {
                sets.insert((*name).to_owned());
            }
            _ => return Err(missing()),
        }
    }
    let wanted_sets = policy
        .zones
        .iter()
        .enumerate()
        .filter(|(_, z)| z.enabled && !z.waiting_for_connection && z.direction() == "direct")
        .map(|(i, _)| format!("awgm_{i:03}"))
        .collect();
    if !probe || returns != expected || sets != wanted_sets {
        return Err(missing());
    }
    verify(&entries, action)
}
fn go_action(
    k: &super::Kernel<'_>,
    entries: &[Vec<&str>],
    action: &str,
    protected: impl Fn(&str) -> bool,
) -> io::Result<String> {
    let missing = || err("недействительный переход AWG2_MULTI, fwmark или маршрут таблицы Go");
    let found = go_action_route(k, entries, action, None)?;
    let iface = found.dev.ok_or_else(missing)?;
    if found.fence != protected(&iface) {
        return Err(missing());
    }
    Ok(iface)
}

struct GoActionRoute {
    slot: usize,
    dev: Option<String>,
    fence: bool,
}

fn go_action_route(
    k: &super::Kernel<'_>,
    entries: &[Vec<&str>],
    action: &str,
    parked: Option<&parked_multi::Parked>,
) -> io::Result<GoActionRoute> {
    let missing = || err("недействительный переход AWG2_MULTI, fwmark или маршрут таблицы Go");
    let raw = action.strip_prefix("AWG2_TO_").ok_or_else(missing)?;
    let mark = u32::from_str_radix(raw, 16).map_err(|_| missing())?;
    let slot = (mark >> 20) & 255;
    if !(1..=64).contains(&slot) || mark != (0x1000_0000 | (slot << 20)) {
        return Err(missing());
    }
    let marked = format!("0x{mark:x}/0x1ff00000");
    let action_rows: Vec<_> = entries
        .iter()
        .filter(|w| w.starts_with(&["-A", action]))
        .map(Vec::as_slice)
        .collect();
    if action_rows
        != [
            ["-A", action, "-j", "MARK", "--set-xmark", marked.as_str()].as_slice(),
            ["-A", action, "-j", "ACCEPT"].as_slice(),
        ]
    {
        return Err(missing());
    }
    let table = (900 + slot).to_string();
    let priority = format!("{}:", 70 + slot);
    let rules = k.listing(plan::Family::V4, &["rule", "show"])?;
    if !rules.lines().any(|l| {
        l.split_ascii_whitespace().collect::<Vec<_>>()
            == [
                priority.as_str(),
                "from",
                "all",
                "fwmark",
                marked.as_str(),
                "lookup",
                table.as_str(),
            ]
    }) {
        return Err(missing());
    }
    if parked.is_some_and(|parked| !parked.guarded()) {
        // A missing table is an iproute2 error on newer kernels. The
        // complete route listing is verified separately by verify_absent.
        return Ok(GoActionRoute { slot: slot as usize, dev: None, fence: false });
    }
    go_slot_route(k, slot as usize)
}

fn go_slot_route(k: &super::Kernel<'_>, slot: usize) -> io::Result<GoActionRoute> {
    let missing = || err("недействительный маршрут таблицы Go");
    let table = (900 + slot).to_string();
    let routes = k.listing(plan::Family::V4, &["route", "show", "table", &table])?;
    let mut dev = None;
    let mut fence = false;
    for row in routes.lines() {
        let words: Vec<_> = row.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["default", "dev", iface, attrs @ ..]
                if plan::iface_ok(iface)
                    && dev.is_none()
                    && attrs.chunks_exact(2).all(|p| {
                        matches!(p, ["scope", "link" | "253"] | ["proto", "boot" | "3"])
                            || p == ["table", table.as_str()]
                    })
                    && attrs.len().is_multiple_of(2) =>
            {
                dev = Some(*iface)
            }
            ["blackhole" | "6", "default", attrs @ ..]
                if !fence
                    && attrs.chunks_exact(2).all(|p| {
                        matches!(p, ["metric", "1000"] | ["proto", "boot" | "3"])
                            || p == ["table", table.as_str()]
                    })
                    && attrs.len().is_multiple_of(2)
                    && attrs.windows(2).any(|p| p == ["metric", "1000"]) =>
            {
                fence = true
            }
            _ => return Err(missing()),
        }
    }
    Ok(GoActionRoute {
        slot,
        dev: dev.map(str::to_owned),
        fence,
    })
}

/// Invoked by the upgrade before Go releases its DNS listener and firewall.
/// Its generation changes on apply and teardown, including the 90s rollback.
pub fn prepare(
    db: &Store,
    run: &dyn Runner,
    endpoint: impl Into<PanelEndpoint>,
) -> io::Result<bool> {
    let runtime =
        nfqws2_awg_profile::runtime::Runtime::new(std::path::Path::new("/"), Default::default());
    let trial = prepare_at(
        db,
        run,
        endpoint.into(),
        || std::thread::sleep(OLD_TRIAL),
        |cfg, iface| {
            let (endpoint, allowed, socket_mark) = runtime.handoff_peer(cfg, iface)?;
            LivePeer::from_uapi(
                std::path::Path::new("/"),
                iface,
                endpoint,
                allowed,
                socket_mark,
                false,
            )
        },
    )?;
    if trial {
        let captured = read(db)?.ok_or_else(|| err("не найден снимок работающей политики Go"))?;
        let direct = captured
            .connected
            .difference(&captured.nested)
            .cloned()
            .collect();
        if let Err(e) =
            nfqws2_awg_profile::runtime::Runtime::stage_go_clients(db, &direct, &captured.nested)
        {
            cancel(db)?;
            return Err(e);
        }
    }
    Ok(trial)
}
#[cfg(test)]
pub(super) fn prepare_after(
    db: &Store,
    run: &dyn Runner,
    port: std::num::NonZeroU16,
    wait: impl FnOnce(),
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    prepare_at(db, run, port.into(), wait, peer)
}
fn prepare_at(
    db: &Store,
    run: &dyn Runner,
    port: PanelEndpoint,
    wait: impl FnOnce(),
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<bool> {
    db.transaction(|tx| {
        if !Journal::read(db)?.idle() {
            return Err(err(
                "сохранён действующий собственный журнал Rust, штатная остановка Go отменена",
            ));
        }
        tx.delete_runtime(FILE)?;
        tx.delete_runtime(CHECK)?;
        tx.delete_runtime(RELEASE)
    })?;
    let doc = nfqws2_awg_profile::read(db)?;
    let mut policy = policy::current(&doc)?;
    if !policy.active {
        return Ok(false);
    }
    let implicit_zone = implicit_multi::zone(&doc, &policy);
    let implicit = implicit_zone.is_some();
    let single = !implicit && legacy::standalone(&policy, &doc);
    if !single && !implicit && !policy.has_explicit_policy()
        || doc["rust_static_routing"].is_object()
    {
        return Err(err(
            "автоматический перенос требует действующей политики зон Go",
        ));
    }
    let source_ipv6 = implicit_zone
        .as_ref()
        .map(|zone| implicit_multi::source_ipv6(&super::kernel(run), &doc, zone))
        .transpose()?
        .flatten();
    let first = live(run, port, &policy, single)?;
    let fingerprint = hash(db, &doc, &policy)?;
    let boot = super::boot_id(&super::kernel(run))?;
    wait();
    if live(run, port, &policy, single)? != first {
        return Err(err(
            "действующая политика изменилась во время проверки подтверждения Go",
        ));
    }
    let created = nfqws2_awg_profile::now();
    let k = super::kernel(run);
    let legacy_full = single.then(|| legacy::ipv6(&k, &doc)).transpose()?;
    let inspect_multi_reject = !single && policy.mode == "full" && policy.has_explicit_policy();
    let go_multi_v6_reject = if inspect_multi_reject {
        legacy::multi_reject(&k)?
    } else {
        None
    };
    let (legacy_scope, warm) = if let Some(state) = &legacy_full {
        super::legacy_scope::capture(&k, db, &doc, state, created)?
    } else {
        (
            None,
            capture_members(run, &crate::sources::expand(db, policy.clone())?, created)?,
        )
    };
    let legacy_dns_bridges = if legacy_scope
        .as_ref()
        .is_some_and(super::legacy_scope::Scope::learner_wanted)
    {
        legacy::dns_bridges(&k, first.pid)?
    } else {
        Vec::new()
    };
    if live(run, port, &policy, single)? != first {
        return Err(err(
            "действующая политика изменилась во время чтения IP-наборов",
        ));
    }
    policy = crate::sources::expand(db, policy)?;
    policy.zones.extend(implicit_zone.iter().cloned());
    policy.active = false;
    let mut capture = Capture {
        created,
        boot,
        policy_hash: fingerprint,
        warm,
        legacy_full,
        implicit_multi_carrier: implicit.then(String::new),
        implicit_multi_parked: None,
        go_multi_v6_reject,
        legacy_scope,
        legacy_dns_bridges,
        connected: first.connected,
        nested: first.nested,
    };
    db.transaction(|tx| {
        let current = nfqws2_awg_profile::read(db)?;
        let config = policy::current(&current)?;
        let still_implicit = implicit_multi::zone(&current, &config).is_some();
        if !config.active
            || (still_implicit != implicit)
            || (!still_implicit && legacy::standalone(&config, &current)) != single
            || hash(db, &current, &config)? != capture.policy_hash
            || implicit && (!Journal::read(db)?.idle() || current["rust_static_routing"].is_object())
        {
            return Err(err(
                "сохранённая политика изменилась во время подготовки перехода",
            ));
        }
        let dynamic = crate::observed::dynamic(&policy);
        let numeric = policy
            .zones
            .iter()
            .filter(|z| z.enabled)
            .flat_map(|z| &z.domains)
            .all(|name| crate::model::ipish(name) || crate::model::catch_all(name));
        if !dynamic && capture.legacy_dns_bridges.is_empty() && !capture.warm.is_empty() {
            return Err(err(
                "динамические IP-наборы не соответствуют режиму сохранённой политики",
            ));
        }
        if implicit && capture.connected.is_empty() && capture.nested.is_empty() {
            let mut intent = seeded(db, &current, None, &capture)?;
            let mut k = super::kernel(run);
            k.track_sockets(&current, &intent);
            k.select_firewall(&mut intent)?;
            let parked = parked_multi::Parked::read(&current, &intent)?;
            let offline = parked.trial_plan(&intent);
            let endpoints = offline.full_endpoints.as_ref().ok_or_else(|| err("нет исключений AWG"))?;
            offline.check_handoff_size()?;
            k.before_go_stop(&offline)?;
            k.guard_before_go_stop(&offline, endpoints)?;
            verify_go_parked(run, &k, &offline, &policy, &parked, false)?;
            capture.implicit_multi_carrier = None;
            capture.implicit_multi_parked = Some(parked);
        } else if single || dynamic || numeric {
            let intent = seeded(db, &current, None, &capture)?;
            if intent.full_endpoints.is_none() {
                intent.reject_active_overlap(&current, &capture.connected)?;
            }
            // Read the existing UAPI peers before stopping Go, so unsupported
            // configurations, endpoint loops and uncovered ranges fail in place.
            let mut resolved = plan::resolve_on(
                &current,
                intent,
                false,
                None,
                Some(plan::Verification::Read(&super::kernel(run))),
                peer,
            )?;
            let mut k = super::kernel(run);
            k.track_sockets(&current, &resolved.plan);
            k.select_firewall(&mut resolved.plan)?;
            if single {
                resolved.plan.set_dns_bridges(&capture.legacy_dns_bridges)?;
            }
            resolved.plan.check_handoff_size()?;
            k.before_go_stop(&resolved.plan)?;
            k.guard_before_go_stop(&resolved.plan, &resolved.endpoints)?;
            if let Some(zone) = &implicit_zone {
                if implicit_multi::source_ipv6(&k, &current, zone)? != source_ipv6 {
                    return Err(err("политика IPv6 изменилась во время проверки AWG2_MULTI"));
                }
                let carrier = implicit_multi::carrier(&resolved.plan)
                    .filter(|id| capture.connected.contains(*id))
                    .ok_or_else(|| err("не подтверждён действующий несущий туннель AWG2_MULTI"))?;
                capture.implicit_multi_carrier = Some(carrier.to_owned());
            }
            if single {
                legacy::verify(&k, db, &resolved.plan, &current)?;
            } else if resolved.plan.ordered_default
                || !resolved.plan.marks.is_empty()
                    && (!resolved.plan.source_ranges.is_empty() || resolved.plan.has_protection())
            {
                ordered::verify(&k, &resolved, &policy, &capture.warm)?;
            } else if policy.global_default_zone().is_some() {
                verify_go_default(run, &k, &resolved.plan, &policy)?;
            }
        }
        if inspect_multi_reject
            && legacy::multi_reject(&super::kernel(run))? != capture.go_multi_v6_reject
        {
            return Err(err(
                "действующее правило AWG2_MULTI для IPv6 изменилось во время подготовки",
            ));
        }
        tx.save_runtime_bounded(FILE, &capture, MAX_SIZE)?;
        tx.save_runtime(
            RELEASE,
            &Release {
                boot: capture.boot.clone(),
                checkpoint: None,
            },
        )
    })?;
    Ok(true)
}
fn read(db: &Store) -> io::Result<Option<Capture>> {
    match db.read_runtime(FILE, MAX_SIZE) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
pub fn pending(db: &Store) -> io::Result<bool> {
    Ok(read(db)?.is_some())
}
pub(super) fn legacy_pending(db: &Store) -> io::Result<bool> {
    Ok(read(db)?.is_some_and(|capture| capture.legacy_full.is_some()))
}
pub(super) fn legacy_dns_bridges(db: &Store) -> io::Result<Option<Vec<String>>> {
    Ok(read(db)?.and_then(|capture| capture.legacy_full.map(|_| capture.legacy_dns_bridges)))
}
pub fn cancel(db: &Store) -> io::Result<()> {
    db.transaction(|tx| tx.delete_runtime(FILE))
}
/// Verify that the candidate being checked still corresponds to the sampled Go policy.
pub struct CheckedTrial {
    pub connected: BTreeSet<String>,
    pub nested: BTreeSet<String>,
    pub policy: Routing,
    pub redirects_dns: bool,
    pub legacy_scoped_dns: bool,
    pub parked: bool,
}

pub(super) struct ParkedTrial {
    pub intended: Plan,
    pub offline: Plan,
    pub endpoints: BTreeSet<IpAddr>,
}

pub(super) fn parked_trial_plan(
    db: &Store,
    k: &super::Kernel<'_>,
    doc: &Value,
    journal: &Journal,
    now: u64,
) -> io::Result<Option<ParkedTrial>> {
    let proof: Check = match db.read_runtime(CHECK, 1 << 16) {
        Ok(proof) => proof,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(parked) = proof.implicit_multi_parked else {
        return Ok(None);
    };
    let invalid = || err("не подтверждена пробная остановленная политика AWG2_MULTI");
    let config = policy::current(doc)?;
    if proof.boot != super::boot_id(k)?
        || proof.boot != journal.boot
        || now.checked_sub(proof.created).is_none_or(|age| age > MAX_AGE + 90)
        || !proof.connected.is_empty()
        || !proof.nested.is_empty()
        || journal.installed.empty()
        || !journal.preparing.is_empty()
        || journal.expires != 0
            && (journal.expires <= now
                || doc["rust_static_routing"]["go_trial"] != true
                || !journal.committed.empty())
        || hash(db, doc, &config)? != proof.hash
    {
        return Err(invalid());
    }
    let mut intended = plan::compile_effective(
        doc,
        crate::sources::current(db, doc)?,
        None,
        true,
        &[],
        journal.installed.layout(),
    )?;
    k.select_firewall(&mut intended)?;
    let offline = parked.trial_plan(&intended);
    if parked_multi::Parked::read(doc, &intended)? != parked
        || journal.installed.as_ref() != &offline
        || journal.expires == 0 && journal.committed.as_ref() != &intended
    {
        return Err(invalid());
    }
    implicit_multi::verify_ipv6(k)?;
    parked.verify_empty_tables(k)?;
    if k.inventory(&journal.claims(), true)? != super::objects(&journal.installed) {
        return Err(invalid());
    }
    let endpoints = intended.full_endpoints.clone().ok_or_else(invalid)?;
    k.guard(&journal.installed, &endpoints)?;
    Ok(Some(ParkedTrial { intended, offline, endpoints }))
}

/// Installer-only acknowledgement for a positively verified parked Go trial.
/// The ordinary routing API continues to report no live forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParkedTrialStatus {
    pub revision: u64,
    pub pending_commit: bool,
}

pub fn parked_trial_status(db: &Store, run: &dyn Runner) -> io::Result<Option<ParkedTrialStatus>> {
    let doc = nfqws2_awg_profile::read(db)?;
    let journal = Journal::read(db)?;
    let k = super::kernel(run);
    parked_trial_plan(db, &k, &doc, &journal, nfqws2_awg_profile::now())
        .map(|checked| checked.map(|trial| ParkedTrialStatus {
            revision: trial.intended.revision,
            pending_commit: journal.expires != 0,
        }))
}

pub fn check_trial(db: &Store, run: &dyn Runner) -> io::Result<CheckedTrial> {
    let proof: Check = db.read_runtime(CHECK, 1 << 16)?;
    let doc = nfqws2_awg_profile::read(db)?;
    let policy = policy::current(&doc)?;
    let journal = Journal::read(db)?;
    if proof.boot != super::boot_id(&super::kernel(run))?
        || nfqws2_awg_profile::now()
            .checked_sub(proof.created)
            .is_none_or(|s| s > MAX_AGE + 90)
        || hash(db, &doc, &policy)? != proof.hash
        || journal.installed.empty()
        || journal.expires != 0 && doc["rust_static_routing"]["go_trial"] != true
    {
        return Err(err(
            "подтверждение относится к другой политике или загрузке роутера",
        ));
    }
    let legacy_scoped_dns =
        journal.installed.legacy_full.is_some() && !journal.installed.dns_bridges.is_empty();
    let parked = proof.implicit_multi_parked.is_some();
    if parked && journal.expires != 0 {
        parked_trial_plan(
            db, &super::kernel(run), &doc, &journal, nfqws2_awg_profile::now(),
        )?.ok_or_else(|| err("нет точной записи остановленной политики AWG2_MULTI"))?;
    }
    let policy = if legacy_scoped_dns {
        journal
            .installed
            .learned
            .as_ref()
            .ok_or_else(|| err("нет снимка зон DNS старого полного туннеля"))?
            .routing()?
    } else {
        crate::sources::expand(db, policy)?
    };
    Ok(CheckedTrial {
        connected: proof.connected,
        nested: proof.nested,
        policy,
        redirects_dns: !journal.installed.dns_bridges.is_empty(),
        legacy_scoped_dns,
        parked,
    })
}
pub fn finished(db: &Store) -> io::Result<()> {
    db.transaction(|tx| tx.delete_runtime(CHECK))
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsClient {
    pub address: IpAddr,
    input: Option<String>,
}
/// Sources for kernel route lookups only. DNS exchanges continue to originate
/// from loopback, and never bind a real LAN client's address.
pub fn dns_clients(run: &dyn Runner, policy: &Routing) -> io::Result<Vec<DnsClient>> {
    let local = DnsClient {
        address: std::net::Ipv4Addr::LOCALHOST.into(),
        input: None,
    };
    let mut clients = BTreeSet::new();
    if policy
        .zones
        .iter()
        .any(|z| z.enabled && !z.source_ips.is_empty())
    {
        let rows = super::kernel(run).call("ip", &["-o", "-4", "addr", "show"])?;
        for row in rows.lines() {
            let w: Vec<_> = row.split_ascii_whitespace().collect();
            let [_, dev, "inet", addr, ..] = w.as_slice() else {
                continue;
            };
            let dev = dev.split('@').next().unwrap_or(dev);
            if !super::valid_dns_bridge(dev) {
                continue;
            }
            let Some((address, _)) = addr.split_once('/') else {
                continue;
            };
            let (Ok(net), Ok(router)) = (addr.parse::<Prefix>(), address.parse::<IpAddr>()) else {
                continue;
            };
            for src in policy
                .zones
                .iter()
                .filter(|z| z.enabled && !z.waiting_for_connection)
                .flat_map(|z| &z.source_ips)
            {
                if let Some(ip) = src.parse::<Prefix>()?.forwarded_sample(net, router) {
                    clients.insert(DnsClient {
                        address: ip,
                        input: Some(dev.to_owned()),
                    });
                }
            }
        }
    }
    Ok(std::iter::once(local).chain(clients).collect())
}

/// Check both the recorded rule and an independent local/forwarded FIB
/// decision. Multiple authenticated physical tunnels may serve one rule.
pub fn check_destination(
    db: &Store,
    run: &dyn Runner,
    ip: IpAddr,
    zone_index: usize,
    client: &DnsClient,
) -> io::Result<()> {
    let journal = Journal::read(db)?;
    let plan = journal.installed;
    let saved = plan
        .learned
        .as_ref()
        .ok_or_else(|| err("нет активного журнала DNS"))?;
    let policy = saved.routing()?;
    let zone = policy
        .zones
        .get(zone_index)
        .filter(|z| z.enabled && !z.waiting_for_connection)
        .ok_or_else(|| err("нет проверяемого правила DNS"))?;
    let static_ip = zone
        .ips
        .iter()
        .chain(&zone.domains)
        .filter(|p| !crate::model::catch_all(p))
        .filter_map(|p| p.parse::<Prefix>().ok())
        .any(|p| p.contains(ip));
    let legacy = plan.legacy_full.is_some();
    let now = nfqws2_awg_profile::now();
    let mut learned = saved
        .members
        .iter()
        .filter(|m| m.zone == zone_index && m.until > now)
        .peekable();
    // A cold Go set can be empty. The loopback probe verifies the DNS
    // listener and the old blanket, without forging the LAN device's source.
    let cold_legacy = legacy && learned.peek().is_none();
    if !zone.only_catch_all() && !static_ip && !cold_legacy && !learned.any(|m| m.ip == ip) {
        return Err(err("DNS-адрес ещё не подтверждён для этой зоны"));
    }
    let flow = plan
        .flows()
        .find(|(s, _)| plan.matches_source(*s, client.address) && s.dest.contains(ip));
    let mut iface = flow.and_then(|(s, p)| plan.effective(s, p));
    let legacy_mark = if legacy {
        let bridge = client
            .input
            .as_deref()
            .ok_or_else(|| err("не определён мост клиента DNS"))?;
        let scope = plan
            .legacy_scope
            .as_ref()
            .ok_or_else(|| err("нет подтверждённых зон старого полного туннеля"))?;
        let mark = scope.v4_dns_mark(&plan, client.address, bridge, ip)?;
        if mark
            == super::legacy_scope::DIRECT
                .split_once('/')
                .map(|(value, _)| value)
        {
            iface = None;
        }
        mark
    } else {
        if zone.direction() == "tunnel"
            && (iface.is_none() || flow.is_none_or(|(_, p)| plan.targets[p].id != zone.tunnel_id))
            || zone.direction() == "direct" && flow.is_some()
        {
            return Err(err(
                "назначение DNS расходится с установленным правилом зоны",
            ));
        }
        None
    };
    let af = if ip.is_ipv4() { "-4" } else { "-6" };
    let ip = ip.to_string();
    let src = client.address.to_string();
    let mut args = vec![af, "route", "get", &ip];
    if let Some(input) = &client.input {
        args.extend(["from", &src, "iif", input]);
    }
    let packet_mark;
    if let Some(mark) = legacy_mark {
        args.extend(["mark", mark]);
    } else if let Some(slot) = iface.and_then(|i| plan.marks.get(i)) {
        packet_mark = super::marked::mark(*slot);
        args.extend(["mark", &packet_mark]);
    }
    let route = super::kernel(run).call("ip", &args)?;
    let words: Vec<_> = route.split_ascii_whitespace().collect();
    let actual = words.windows(2).find(|w| w[0] == "dev").map(|w| w[1]);
    if !actual.is_some_and(|dev| {
        iface.map_or_else(
            || !dev.starts_with("awg") && dev != "lo",
            |expected| dev == expected,
        )
    }) {
        return Err(err(
            "фактический интерфейс DNS-адреса не соответствует проверяемой зоне",
        ));
    }
    Ok(())
}
fn seeded(
    db: &Store,
    doc: &Value,
    snapshot: Option<&DnsSnapshot>,
    proof: &Capture,
) -> io::Result<Plan> {
    let routing = if proof.legacy_scope.as_ref().is_some_and(super::legacy_scope::Scope::learner_wanted) {
        super::learning::legacy_policy(db, doc)?
    } else {
        crate::sources::current(db, doc)?
    };
    let revision = doc["routing_revision"].as_u64().unwrap_or_default();
    plan::compile_effective(
        doc,
        routing,
        snapshot,
        false,
        &proof.warm,
        plan::Layout {
            go_ipv4: proof.legacy_full.is_none(),
            implicit_go_full_revision: (proof.implicit_multi_carrier.is_some()
                || proof.implicit_multi_parked.is_some()).then_some(revision),
            go_multi_v6_reject: proof.go_multi_v6_reject.clone().map(|wan| (revision, wan)),
            legacy_revision: proof.legacy_full.as_ref().map(|_| revision),
            legacy_full: proof.legacy_full.clone(),
            legacy_scope: proof.legacy_scope.clone(),
            ..Default::default()
        },
    )
}

pub(super) fn candidate(
    db: &Store,
    tx: &Transaction<'_>,
    run: &dyn Runner,
    doc: &Value,
    now: u64,
    snapshot: Option<&DnsSnapshot>,
    peer: impl FnMut(&Value, &str) -> io::Result<LivePeer>,
) -> io::Result<Option<(Plan, BTreeSet<IpAddr>)>> {
    let Some(proof) = read(db)? else {
        return Ok(None);
    };
    tx.delete_runtime(FILE)?;
    let config = policy::current(doc)?;
    if now.checked_sub(proof.created).is_none_or(|n| n > MAX_AGE)
        || proof.boot != super::boot_id(&super::kernel(run))?
        || !config.active
        || hash(db, doc, &config)? != proof.policy_hash
    {
        return Err(err(
            "снимок действующей политики Go устарел, повторите подготовку",
        ));
    }
    let still_implicit = implicit_multi::zone(doc, &config).is_some();
    let parked = proof.implicit_multi_parked.as_ref();
    if still_implicit != (proof.implicit_multi_carrier.is_some() || parked.is_some())
        || parked.is_some() && (proof.implicit_multi_carrier.is_some() || snapshot.is_some()
            || !proof.connected.is_empty() || !proof.nested.is_empty() || !proof.warm.is_empty())
        || (!still_implicit && legacy::standalone(&config, doc)) != proof.legacy_full.is_some() {
        return Err(err(
            "исходный тип маршрутизации Go не соответствует политике",
        ));
    }
    if proof.go_multi_v6_reject.is_some()
        && (proof.legacy_full.is_some() || config.mode != "full" || !config.has_explicit_policy())
    {
        return Err(err(
            "исходное правило AWG2_MULTI для IPv6 не соответствует политике",
        ));
    }
    if still_implicit {
        if !Journal::read(db)?.idle() || doc["rust_static_routing"].is_object() {
            return Err(err("сохранён действующий собственный журнал Rust"));
        }
        implicit_multi::verify_ipv6(&super::kernel(run))?;
    }
    let mut intent = seeded(db, doc, snapshot, &proof)?;
    let (mut plan, endpoints) = if let Some(parked) = parked {
        let k = super::kernel(run);
        k.select_firewall(&mut intent)?;
        if parked_multi::Parked::read(doc, &intent)? != *parked {
            return Err(err("изменился состав остановленной политики AWG2_MULTI"));
        }
        parked.verify_absent(&k)?;
        let offline = parked.trial_plan(&intent);
        let endpoints = offline.full_endpoints.clone().ok_or_else(|| err("нет исключений AWG"))?;
        k.guard(&offline, &endpoints)?;
        (offline, endpoints)
    } else {
        let live = plan::resolve_on(
            doc,
            intent,
            false,
            None,
            Some(plan::Verification::Read(&super::kernel(run))),
            peer,
        )?;
        if let Some(expected) = &proof.implicit_multi_carrier {
            if implicit_multi::carrier(&live.plan) != Some(expected.as_str()) || !proof.connected.contains(expected) {
                return Err(err("изменился действующий несущий туннель AWG2_MULTI"));
            }
        }
        (live.plan, live.endpoints)
    };
    if plan.legacy_full.is_some() {
        plan.set_dns_bridges(&proof.legacy_dns_bridges)?;
    }
    tx.save_runtime(
        CHECK,
        &Check {
            boot: proof.boot,
            created: proof.created,
            hash: proof.policy_hash,
            connected: proof.connected,
            nested: proof.nested,
            implicit_multi_parked: proof.implicit_multi_parked,
        },
    )?;
    Ok(Some((plan, endpoints)))
}
