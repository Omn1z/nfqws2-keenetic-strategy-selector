use super::{
    diagnostics::Trace,
    discovery::{self, InformEvidence, Peer},
    inform::state::{DiscoveryEvent, Input, KnownTarget, Plan, Selection, Source, State, Wan},
    lease_store,
    observer::Reader,
    Event,
};
use std::{
    collections::BTreeMap,
    future::pending,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::watch, time::Instant as AsyncInstant};

#[derive(Default)]
pub(super) struct Runtime {
    pub(super) state: State,
    passive_revision: Option<(u64, u64)>,
}

impl Runtime {
    pub(super) fn known(&self, saved: BTreeMap<String, lease_store::Target>) -> Vec<KnownTarget> {
        let mut targets = BTreeMap::new();
        for (iface, entry) in saved {
            targets.insert(
                iface.clone(),
                KnownTarget {
                    iface,
                    wan_key: entry.wan_key,
                    client: entry.client,
                    server: entry.server,
                    stamp: entry.stamp,
                    observed_at_epoch: None,
                },
            );
        }
        for target in self.state.known() {
            targets.insert(target.iface.clone(), target.clone());
        }
        targets.into_values().collect()
    }

    pub(super) fn plan(
        &mut self,
        proof: &InformEvidence,
        input: Input<'_>,
        passive: Option<(&Wan, (u64, u64))>,
        now: AsyncInstant,
        trace: &Trace,
    ) -> Plan {
        for known in proof.restored.iter().chain(&proof.ring) {
            if let Some(wan) = proof.owners.iter().find(|wan| {
                wan.iface == known.iface && wan.key == known.wan_key && wan.client == known.client
            }) {
                self.state.remember(wan, known.clone(), &proof.local);
            }
        }
        if let Some((wan, revision)) =
            passive.filter(|(_, revision)| Some(*revision) != self.passive_revision)
        {
            self.state.native_reply(wan);
            self.passive_revision = Some(revision);
        }
        self.state
            .plan_report(input, now, |event| report_discovery(trace, event))
    }

    pub(super) fn targets(
        &self,
        mut saved: BTreeMap<String, lease_store::Target>,
        key: &str,
        proof: &InformEvidence,
    ) -> Option<BTreeMap<String, lease_store::Target>> {
        if key.is_empty() {
            return None;
        }
        saved.retain(|_, target| target.wan_key == key && proof.wan_ips.contains(&target.client));
        for target in self
            .state
            .known()
            .filter(|target| target.wan_key == key && proof.wan_ips.contains(&target.client))
        {
            if !saved.contains_key(&target.iface) && saved.len() == lease_store::MAX_RECORDS {
                let previous = saved.iter().find_map(|(iface, existing)| {
                    (existing.client == target.client).then(|| iface.clone())
                });
                let Some(previous) = previous else { continue };
                saved.remove(&previous);
            }
            saved.insert(
                target.iface.clone(),
                lease_store::Target {
                    wan_key: target.wan_key.clone(),
                    client: target.client,
                    server: target.server,
                    stamp: target.stamp.clone(),
                },
            );
        }
        Some(saved)
    }
}

pub(super) fn report_discovery(trace: &Trace, event: DiscoveryEvent<'_>) {
    match event {
        DiscoveryEvent::Target {
            wan,
            server,
            prefer_broadcast,
        } => trace.step(
            "discovery.target",
            &format!(
                "{} / {}; клиент {}; DHCP-сервер {server}; broadcast={prefer_broadcast}",
                wan.iface, wan.device, wan.client
            ),
        ),
        DiscoveryEvent::TargetRejected(iface) => trace.step(
            "discovery.target",
            &format!("{iface}: сохранённый DHCP-сервер не прошёл проверку текущего WAN"),
        ),
        DiscoveryEvent::Cached(options) => trace.step(
            "discovery.cached",
            &format!(
                "{}: действующий ответ DHCPINFORM сохранён в кеше",
                options.wan.iface
            ),
        ),
        DiscoveryEvent::Cooldown { iface, next } => trace.step(
            "discovery.cooldown",
            &format!(
                "{iface}: повторная попытка после {}",
                super::future(next.saturating_duration_since(AsyncInstant::now()))
            ),
        ),
        DiscoveryEvent::Broadcast { fallback } => trace.step(
            "discovery.broadcast",
            &format!("Выбран WAN для broadcast; переход с unicast={fallback}"),
        ),
        DiscoveryEvent::NextBroadcast(iface) => trace.step(
            "discovery.mode",
            &format!("{iface}: таймаут unicast; следующая попытка через broadcast"),
        ),
    }
}

pub(super) fn input<'a>(key: &'a str, proof: &'a InformEvidence, source: Source) -> Input<'a> {
    Input {
        key,
        owners: &proof.owners,
        local: &proof.local,
        source,
    }
}

pub(super) async fn confirmed(
    source: &Arc<dyn discovery::Source>,
    owner: &Wan,
    deadline: Instant,
) -> bool {
    if Instant::now() >= deadline {
        return false;
    }
    let source = source.clone();
    let owner = owner.clone();
    tokio::task::spawn_blocking(move || source.confirm_inform(&owner, deadline))
        .await
        .unwrap_or(false)
}

pub(super) async fn superseded(
    lifetime: &mut watch::Receiver<bool>,
    passive: Option<(&Reader, u64)>,
    deadline: AsyncInstant,
) {
    let changed = async {
        if let Some((reader, baseline)) = passive {
            if reader.clone().wait(baseline, deadline).await.is_some() {
                return;
            }
        }
        pending::<()>().await;
    };
    tokio::select! {
        _ = lifetime.wait_for(|stopped| *stopped) => (),
        _ = changed => (),
    }
}

pub(super) fn apply(
    selection: Selection,
    base: io::Result<Vec<Peer>>,
    ppp: &[Peer],
) -> io::Result<Vec<Peer>> {
    let options = match selection {
        Selection::Inform(options) if options.expires > AsyncInstant::now() => options,
        Selection::Fallback(Some(error)) if base.is_err() => return Err(error),
        _ => return base,
    };
    let mut peers: Vec<_> = options
        .dns
        .into_iter()
        .map(|ip| Peer {
            addr: SocketAddr::new(ip.into(), 53),
            device: options.wan.device.clone(),
            expires: Some(options.expires.into_std()),
        })
        .collect();
    for peer in ppp {
        if peers.len() == 8 {
            break;
        }
        if peer.expires.is_none_or(|expires| expires > Instant::now())
            && !peers.iter().any(|existing| existing.addr == peer.addr)
        {
            peers.push(peer.clone());
        }
    }
    Ok(peers)
}

pub(super) fn report_start(
    trail: &Event<'_>,
    owner: &Wan,
    server: Option<std::net::Ipv4Addr>,
    remaining: Duration,
) {
    let mode = if server.is_some() {
        "unicast"
    } else {
        "broadcast"
    };
    let destination = server.unwrap_or(std::net::Ipv4Addr::BROADCAST);
    trail.step(
        "dhcp.start",
        &format!(
            "{mode}: WAN={}, client={}:68, destination={destination}:67; окно ответа={} мс",
            owner.device,
            owner.client,
            remaining.as_millis().min(1200)
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::super::inform::state::Options;
    use super::*;

    #[test]
    fn inform_options_replace_old_dhcp_but_keep_independent_ppp_until_exact_expiry() {
        let address = |text: &str, device: &str| Peer {
            addr: text.parse().unwrap(),
            device: device.into(),
            expires: None,
        };
        let old_dhcp = address("192.0.2.55:53", "eth3");
        let ppp = address("192.0.2.54:53", "ppp0");
        let expires = AsyncInstant::now() + Duration::from_secs(30);
        let options = Options {
            wan: Wan {
                key: "sample".into(),
                iface: "ISP".into(),
                device: "eth3".into(),
                index: 5,
                mac: [2, 0, 0, 0, 0, 1],
                client: "198.51.100.10".parse().unwrap(),
            },
            dns: vec!["192.0.2.53".parse().unwrap()],
            expires,
        };
        let peers = apply(
            Selection::Inform(options.clone()),
            Ok(vec![old_dhcp.clone(), ppp.clone()]),
            std::slice::from_ref(&ppp),
        )
        .unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].addr, "192.0.2.53:53".parse().unwrap());
        assert_eq!(peers[0].expires, Some(expires.into_std()));
        assert_eq!(peers[1], ppp);
        let stale = Options {
            expires: AsyncInstant::now(),
            ..options
        };
        let peers = apply(Selection::Inform(stale), Ok(vec![old_dhcp.clone()]), &[]).unwrap();
        assert_eq!(peers, [old_dhcp]);
    }

    #[test]
    fn target_write_keeps_unverified_alias_under_same_wan_and_prunes_on_proved_change() {
        let state = Runtime::default();
        let target = lease_store::Target {
            wan_key: "active".into(),
            client: "198.51.100.10".parse().unwrap(),
            server: "198.51.100.1".parse().unwrap(),
            stamp: String::new(),
        };
        let saved = BTreeMap::from([("ISP".into(), target.clone())]);
        let proof = InformEvidence {
            wan_ips: vec![target.client],
            ..Default::default()
        };
        assert!(state.targets(saved.clone(), "", &proof).is_none());
        assert_eq!(state.known(saved.clone())[0].iface, "ISP");
        assert_eq!(
            state
                .targets(saved.clone(), "active", &proof)
                .unwrap()
                .len(),
            1
        );
        assert!(state.targets(saved, "changed", &proof).unwrap().is_empty());
    }

    #[test]
    fn inform_after_restart_uses_restored_verified_server_without_a_ring_ack() {
        let owner = Wan {
            key: "active".into(),
            iface: "ISP".into(),
            device: "eth3".into(),
            index: 5,
            mac: [2, 0, 0, 0, 0, 1],
            client: "198.51.100.10".parse().unwrap(),
        };
        let server = "198.51.100.1".parse().unwrap();
        let proof = InformEvidence {
            owners: vec![owner.clone()],
            restored: vec![KnownTarget {
                iface: owner.iface.clone(),
                wan_key: owner.key.clone(),
                client: owner.client,
                server,
                stamp: String::new(),
                observed_at_epoch: None,
            }],
            ..Default::default()
        };
        let source = Source::Fallback {
            has_verified_peer: false,
        };
        let mut runtime = Runtime::default();
        let Plan::Probe(probe) = runtime.plan(
            &proof,
            input(&owner.key, &proof, source),
            None,
            AsyncInstant::now(),
            &Trace::default(),
        ) else {
            panic!("expected a unicast probe from reattested saved data");
        };
        assert_eq!(probe.target().server, Some(server));
        assert_eq!(probe.wan(), &owner);
    }
}
