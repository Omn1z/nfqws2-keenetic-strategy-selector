use super::{status, task, ApiError, Json, Router, Shared, State, Value};
use crate::dnsserver::{
    ActiveDnsRevalidation, ArchiveResolver, FailedRoute, ManagedOriginReceipt, RoutePublication,
};
use axum::routing::post;
use nfqws2_awg_profile::RoutedEndpointLaunch;
use nfqws2_awg_rules::kernel::{self, DnsRequest, DnsSnapshot, LivePeer, Operation, Schedule};
use nfqws2_router_command::System;
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::{
    sync::{watch, Mutex},
    task::JoinHandle,
    time::{self, Interval, MissedTickBehavior},
};
mod fw4_events;
mod observer;
mod redirect;
mod static_dns;
mod warm_named;
#[cfg(test)]
pub(crate) use static_dns::{
    static_apply_for_test, static_initial_apply_for_test, static_proposal_apply_for_test,
    StaticApplyFixture, StaticApplyFixtureFailure, StaticInitialApplyFixture,
};
pub(crate) use warm_named::prepare as prepare_profile_replacement_names;

pub struct Service {
    observer: observer::Gate,
    worker: Mutex<Option<(watch::Sender<usize>, JoinHandle<()>)>>,
    operations: std::sync::Mutex<()>,
    generation: std::sync::atomic::AtomicUsize,
    resolv_conf: PathBuf,
    router_root: PathBuf,
    resolving: std::sync::Mutex<()>,
    static_dns: std::sync::Mutex<Option<static_dns::Hint>>,
    warm_named: std::sync::Mutex<warm_named::State>,
}
impl Service {
    pub fn new(root: &Path) -> Self {
        Self {
            observer: Default::default(),
            worker: Default::default(),
            operations: Default::default(),
            generation: Default::default(),
            resolving: Default::default(),
            static_dns: Default::default(),
            warm_named: Default::default(),
            resolv_conf: root.join("etc/resolv.conf"),
            router_root: root.to_owned(),
        }
    }
    fn notify_rearm(&self) {
        let generation = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        if let Some((wake, _)) = self.worker.blocking_lock().as_ref() {
            wake.send_replace(generation);
        }
    }
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/awg2/routing/apply", post(apply))
        .route("/api/awg2/routing/commit", post(commit))
        .route("/api/awg2/routing/teardown", post(teardown))
}
fn run(s: &Shared, op: Operation, snapshot: Option<&DnsSnapshot>) -> io::Result<()> {
    if op == Operation::Recover
        && kernel::pending_active_replacement_retirement(&s.store)?
            .is_some_and(|owner| owner.nested.is_some())
    {
        // A crash can leave half of the retired socket's RPDB pair present.
        // Retry the sealed cleanup before the ordinary inventory reads it.
        crate::awg_profiles::finish_active_replacement_retirement(s)?;
    }
    let rearm = matches!(op, Operation::Recover | Operation::Refresh)
        && snapshot.is_none()
        && kernel::disabled_replacement_rearm_needs_dns(&s.store)?;
    if rearm {
        let request = kernel::dormant_firmware_dns(&s.store)?;
        publish_after(s, op, || redirect::operate(s, op, None, None))?;
        let restored = request.and_then(|request| {
            let revision = request.restored_revision(&s.store).ok()??;
            let publication = s.route_kernel.observer.confirmed_firmware_publication()?;
            (publication.revision == revision).then_some((request, publication))
        });
        if let Some((request, publication)) = restored {
            s.dnsserver
                .restore_firmware_hints(request.transfer_stamp().0, publication);
        }
        Ok(())
    } else if op == Operation::Refresh && snapshot.is_none() {
        run_firmware_refresh(s)
    } else {
        publish_after(s, op, || redirect::operate(s, op, snapshot, None))
    }
}

fn run_firmware_refresh(s: &Shared) -> io::Result<()> {
    let observer = &s.route_kernel.observer;
    let previous = observer
        .confirmed_firmware_publication()
        .filter(|publication| s.dnsserver.has_live_firmware_hints(*publication))
        .and_then(|publication| {
            let basis = kernel::confirmed_firmware_refresh_basis(&s.store).ok()??;
            (publication.revision == basis.revision()).then_some((publication, basis))
        });
    let Some((old, basis)) = previous else {
        return publish_after(s, Operation::Refresh, || {
            redirect::operate(s, Operation::Refresh, None, None)
        });
    };
    let unchanged = std::cell::Cell::new(false);
    publish_after(s, Operation::Refresh, || {
        unchanged.set(redirect::operate_firmware_refresh(s)?);
        Ok(())
    })?;
    if let Some(new) = observer
        .confirmed_firmware_publication()
        .filter(|new| unchanged.get() && new.revision == basis.revision())
    {
        let _ = basis.continue_if_current(&s.store, || {
            s.dnsserver.continue_firmware_hints(old, new);
        });
    }
    Ok(())
}

fn routing_live_peer(s: &Shared, cfg: &Value, iface: &str) -> io::Result<LivePeer> {
    routing_live_peer_with_probe(s, cfg, iface, None)
}

fn routing_live_peer_with_probe(
    s: &Shared,
    cfg: &Value,
    iface: &str,
    fresh_target: Option<SocketAddr>,
) -> io::Result<LivePeer> {
    if fresh_target.is_none() {
        let go = match s.awg_runtime.go_nested_trial_peer(&s.store, cfg, iface)? {
            Some(peer) => Some(peer),
            None => s
                .awg_runtime
                .go_nested_confirmed_peer(&s.store, cfg, iface)?,
        };
        if let Some((mut allowed, transport)) = go {
            let peer = &transport.peer;
            let reachable =
                s.awg_runtime
                    .routing_policy_ipv6(cfg, iface, peer.endpoint, &mut allowed);
            return Ok(LivePeer::from_uapi(
                &s.route_kernel.router_root,
                iface,
                peer.endpoint,
                allowed,
                peer.socket_mark,
                reachable,
            )?
            .with_ordinary_preference(s.awg_runtime.prefers_ordinary_routing(
                cfg,
                iface,
                peer.socket_mark,
            ))
            .with_nested_transport(Some(transport)));
        }
    }
    let (endpoint, allowed, socket_mark, ipv6_reachable, fresh_probe) =
        if let Some(expected) = fresh_target {
            let (endpoint, allowed, mark, fresh) = s
                .awg_runtime
                .routing_policy_peer_with_fresh_ipv6_probe(cfg, iface, expected)?;
            (endpoint, allowed, mark, fresh == Some(true), fresh)
        } else {
            let (endpoint, allowed, mark, reachable) =
                match s.awg_runtime.routing_policy_peer(cfg, iface) {
                    Ok(peer) => peer,
                    Err(error) => {
                        let Some(startup) = kernel::cold_numeric_startup(&s.store, iface)? else {
                            return Err(error);
                        };
                        let peer = s.awg_runtime.routing_cold_numeric_replacement_peer(
                            &s.store,
                            &startup.owner,
                            startup.binding,
                            s.config.awg_wan_ifaces(),
                        )?;
                        return Ok(LivePeer::from_uapi(
                            &s.route_kernel.router_root,
                            iface,
                            peer.endpoint,
                            peer.allowed.clone(),
                            peer.socket_mark,
                            false,
                        )?
                        .with_active_replacement_peer(Some(peer)));
                    }
                };
            (endpoint, allowed, mark, reachable, None)
        };
    let peer = LivePeer::from_uapi(
        &s.route_kernel.router_root,
        iface,
        endpoint,
        allowed,
        socket_mark,
        ipv6_reachable,
    )?
    .with_ordinary_preference(
        s.awg_runtime
            .prefers_ordinary_routing(cfg, iface, socket_mark),
    )
    .with_fresh_bound_ipv6_probe(fresh_probe);
    if peer.nested_mtu.is_some() {
        // Rules can park the unconfirmed path and retain an eligible reserve.
        let nested = s
            .awg_runtime
            .routing_nested_transport(&s.store, iface, endpoint, socket_mark)
            .ok()
            .flatten();
        let unselected_permanent = nested.is_some()
            && cfg["client"]["double_tunnel_mode"] == "permanent"
            && cfg["routing"]["active"] != true;
        let native_replacement = if unselected_permanent
            || kernel::active_replacement_native_witness_needed(&s.store, iface).unwrap_or(false)
        {
            s.awg_runtime
                .routing_nested_active_replacement_peer(
                    &s.store,
                    iface,
                    endpoint,
                    socket_mark,
                    s.config.awg_wan_ifaces(),
                )
                .ok()
                .flatten()
        } else {
            None
        };
        return Ok(peer
            .with_nested_transport(nested)
            .with_active_replacement_peer(native_replacement));
    }
    let fresh_full = cfg["routing"]["mode"] == "full"
        && kernel::fresh_full_reserve_native_witness_needed(&s.store, iface).unwrap_or(false);
    let warm_owner = if endpoint.is_ipv6() {
        let pending = kernel::warm_named_native_owner(&s.store, iface, endpoint)?;
        if pending.is_some() {
            pending
        } else {
            kernel::established_warm_owner(&s.store, iface, endpoint, s.config.awg_wan_ifaces())?
        }
    } else {
        None
    };
    let native_replacement = if let Some(owner) = warm_owner {
        s.awg_runtime
            .routing_warm_named_ipv6_peer(&s.store, &owner, endpoint, s.config.awg_wan_ifaces())
            .ok()
    } else if fresh_full
        || kernel::active_replacement_native_witness_needed(&s.store, iface).unwrap_or(false)
    {
        s.awg_runtime
            .routing_active_replacement_peer(
                &s.store,
                iface,
                endpoint,
                socket_mark,
                s.config.awg_wan_ifaces(),
            )
            .ok()
            .flatten()
    } else {
        None
    };
    let peer = peer.with_active_replacement_peer(native_replacement);
    let Some(primary) = cfg["endpoint"]
        .as_str()
        .and_then(|value| value.trim().parse::<SocketAddr>().ok())
    else {
        return Ok(peer);
    };
    let primary_is_elsewhere = primary.ip().to_canonical() != endpoint.ip().to_canonical();
    let backup = if primary_is_elsewhere {
        s.awg_runtime
            .routing_direct_backup(
                &s.store,
                iface,
                endpoint,
                socket_mark,
                s.config.awg_wan_ifaces(),
            )
            .ok()
            .flatten()
    } else {
        None
    };
    let predecessor = if primary_is_elsewhere || primary.port() != endpoint.port() {
        s.awg_runtime
            .routing_endpoint_predecessor(
                &s.store,
                iface,
                endpoint,
                socket_mark,
                s.config.awg_wan_ifaces(),
            )
            .ok()
            .flatten()
    } else {
        None
    };
    Ok(peer
        .with_direct_backup(backup)
        .with_endpoint_predecessor(predecessor))
}

fn publish_after(
    s: &Shared,
    op: Operation,
    operation: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    publish_after_classified(s, op, || {
        let result = operation();
        let outcome = observer::PublicationOutcome::from_result(op, &result);
        (result, outcome)
    })
}

fn publish_after_classified(
    s: &Shared,
    op: Operation,
    operation: impl FnOnce() -> (io::Result<()>, observer::PublicationOutcome),
) -> io::Result<()> {
    s.route_kernel.observer.begin(op)?;
    s.dnsserver.invalidate_routing_confirmations();
    let (result, outcome) = operation();
    let failed = op == Operation::Apply && result.is_err();
    let result = publish_observation(s, result, outcome);
    warm_named::replace_capture(s, failed);
    result
}

fn publish_observation(
    s: &Shared,
    result: io::Result<()>,
    outcome: observer::PublicationOutcome,
) -> io::Result<()> {
    s.awg_runtime.invalidate_routing();
    let (dns, sni) = match kernel::observations(&s.store) {
        Ok((dns, sni)) => (Ok(dns), sni),
        Err(error) => (Err(error), Ok(None)),
    };
    let published = s.route_kernel.observer.publish_write(dns, outcome);
    s.trace.awg.publish_sni(sni);
    result.and(published)
}

pub(crate) fn named_dns_failure_epoch(s: &Shared) -> Option<u64> {
    s.route_kernel.observer.failure_epoch()
}

pub(crate) fn validate_profile_endpoint(
    s: &Shared,
    change: &nfqws2_awg_profile::RoutedMtuChange,
) -> io::Result<RoutedEndpointLaunch> {
    kernel::validate_endpoint_edit_launch(&s.store, &System, change, s.config.awg_wan_ifaces())
}

pub(crate) fn park_profile_mtu(
    s: &Shared,
    change: &nfqws2_awg_profile::RoutedMtuChange,
) -> io::Result<()> {
    // The caller already holds the routing lock and the profile manager's
    // client lock. This operation only checks the journal and the kernel.
    publish_after(s, Operation::Refresh, || {
        kernel::prepare_mtu_edit_with_wan(&s.store, &System, change, s.config.awg_wan_ifaces())
    })
}

pub(crate) fn pending_endpoint_launch(
    s: &Shared,
    change: &nfqws2_awg_profile::RoutedMtuChange,
) -> io::Result<RoutedEndpointLaunch> {
    kernel::pending_endpoint_launch(&s.store, &System, change, s.config.awg_wan_ifaces())
}

pub(crate) fn park_endpoint_retry(
    s: &Shared,
    change: &nfqws2_awg_profile::RoutedMtuChange,
    endpoint: SocketAddr,
) -> io::Result<()> {
    publish_after(s, Operation::Refresh, || {
        kernel::prepare_endpoint_retry(
            &s.store,
            &System,
            change,
            endpoint,
            s.config.awg_wan_ifaces(),
        )
    })
}

pub(crate) fn change_profile<T>(
    s: &Shared,
    apply: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let _guard = s
        .route_kernel
        .operations
        .lock()
        .map_err(|_| io::Error::other("менеджер маршрутов недоступен"))?;
    apply_profile(s, apply)
}

/// Called inside the route operation. Publish after the native profile
/// callback releases its owner and Store locks; the caller schedules replay
/// only after dropping the outer route operation lock too.
pub(crate) fn observe_active_replacement(
    s: &Shared,
    source: &str,
    renewed: Option<&ActiveDnsRevalidation>,
    withdraw: bool,
    warm: Option<&warm_named::WarmConfirmation>,
    replace: impl FnOnce(&dyn Fn(bool) -> io::Result<()>) -> io::Result<Option<String>>,
) -> io::Result<(Option<String>, Option<RoutePublication>)> {
    let scope = if withdraw {
        kernel::disabled_replacement_dns_redirects(&s.store, source)?
    } else if let Some(renewed) = renewed {
        let request = renewed.proof.request();
        Some((request.revision(), request.bridges().to_vec()))
    } else {
        kernel::active_replacement_dns_redirects(&s.store, source)?
    };
    if let Some(warm) = warm {
        if withdraw || renewed.is_some() || scope.is_some() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let opened = std::cell::Cell::new(false);
        let result = replace(&|require_fresh| {
            if !require_fresh {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            warm.verify(s)?;
            s.route_kernel.observer.begin(Operation::Apply)?;
            s.dnsserver.invalidate_routing_confirmations();
            opened.set(true);
            Ok(())
        });
        if opened.get() {
            let result = warm_named::publication(s, result);
            warm_named::replace_capture(s, false);
            return result.map(|warning| (warning, None));
        }
        return result.map(|warning| (warning, None));
    }
    let Some((revision, bridges)) = scope else {
        return replace(&|_| Ok(())).map(|warning| (warning, None));
    };
    let observer = &s.route_kernel.observer;
    let previous = withdraw
        .then(|| observer.confirmed_firmware_publication())
        .flatten();
    let ready = |require_fresh: bool| {
        observer.replay_publication().is_some_and(|active| {
            active.revision == revision
                && renewed.is_none_or(|renewed| {
                    active == renewed.publication
                        && (!require_fresh || tokio::time::Instant::now() < renewed.expires)
                })
        })
    };
    if !withdraw {
        if !ready(true) {
            return Err(io::Error::other(
                "действующая политика DNS ещё не подтверждена",
            ));
        }
        redirect::prepare_active_replacement(s, &bridges)?;
    }
    let opened = std::cell::Cell::new(false);
    let result = replace(&|require_fresh| {
        if !withdraw && !ready(require_fresh) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        observer.begin(Operation::Apply)?;
        s.dnsserver.invalidate_routing_confirmations();
        opened.set(true);
        Ok(())
    });
    if !opened.get() {
        return result.map(|warning| (warning, None));
    }
    let written = result
        .as_ref()
        .map(|_| ())
        .map_err(|error| io::Error::new(error.kind(), error.to_string()));
    let outcome = observer::PublicationOutcome::from_result(Operation::Apply, &written);
    let published = publish_observation(s, written, outcome);
    if let Some(previous) = previous.filter(|p| result.is_ok() && p.revision == revision) {
        if let Ok(Some(request)) = kernel::dormant_firmware_dns(&s.store) {
            let (stamp, revision) = request.transfer_stamp();
            if previous.revision == revision {
                s.dnsserver.park_firmware_hints(previous, stamp);
            }
        }
    }
    let sockets = if withdraw {
        kernel::redirect_bridges(&s.store, false).and_then(|names| {
            tokio::runtime::Handle::current().block_on(s.dnsserver.set_routing_redirect(&names))
        })
    } else {
        Ok(())
    };
    s.route_kernel.generation.fetch_add(1, Ordering::AcqRel);
    let mut warning = result?;
    let replay = if let Err(error) = published.and(sockets) {
        s.logs.append("awg2", "warn", &error.to_string());
        let message = "перенос сохранён, подтверждение DNS будет повторено";
        warning = Some(warning.map_or_else(|| message.into(), |old| format!("{old}. {message}")));
        None
    } else {
        observer.replay_publication()
    };
    Ok((warning, replay))
}

/// Resolve outside route and client operations. The kernel receives only an
/// exact, current, complete RRset and independently checks the held receipt.
pub(crate) fn prepare_active_replacement_dns(
    s: &Shared,
    source: &str,
) -> io::Result<Option<ActiveDnsRevalidation>> {
    let Some(request) = kernel::active_replacement_dns_revalidation(&s.store, source)? else {
        return Ok(None);
    };
    let publication = s
        .route_kernel
        .observer
        .replay_publication()
        .filter(|active| active.revision == request.revision())
        .ok_or(io::ErrorKind::WouldBlock)?;
    let deadline = tokio::time::Instant::now() + DNS_BUDGET;
    let handle = tokio::runtime::Handle::current();
    let state = s.clone();
    let resolve = handle.spawn(async move {
        state
            .dnsserver
            .revalidate_active_replacement(request, publication, deadline)
            .await
    });
    handle
        .block_on(resolve)
        .map_err(io::Error::other)?
        .map(Some)
}

fn prepare_pending_replacement_dns(
    s: &Shared,
) -> io::Result<Option<kernel::ActiveReplacementDnsRetryProof>> {
    let Some(request) = kernel::pending_active_replacement_dns_retry(&s.store)? else {
        return Ok(None);
    };
    let expected = request.clone();
    let state = s.clone();
    let runtime = tokio::runtime::Handle::current();
    let deadline = tokio::time::Instant::now() + DNS_BUDGET;
    let task = runtime.spawn(async move {
        state
            .dnsserver
            .revalidate_pending_replacement(request, deadline, || {
                kernel::pending_active_replacement_dns_retry(&state.store)
                    .is_ok_and(|current| current.as_ref() == Some(&expected))
            })
            .await
    });
    runtime.block_on(task).map_err(io::Error::other)?.map(Some)
}

pub(crate) fn disable_profile(s: &Shared, server: Option<&str>) -> io::Result<()> {
    change_profile(s, || {
        let operation = Operation::Refresh;
        let observed = std::cell::Cell::new(false);
        let result = s
            .awg_runtime
            .disable_with_routing(&s.store, server, |request| {
                s.route_kernel.observer.begin(operation)?;
                observed.set(true);
                s.dnsserver.invalidate_routing_confirmations();
                kernel::disable_routed_profile(
                    &s.store,
                    &System,
                    request,
                    s.config.awg_wan_ifaces(),
                )
            });
        if observed.get() {
            let outcome = observer::PublicationOutcome::from_result(operation, &result);
            publish_observation(s, result, outcome)
        } else {
            result
        }
    })
}

pub(crate) fn enable_profile(
    s: &Shared,
    server: Option<&str>,
    enable: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    change_profile(s, || {
        let rearm = kernel::routed_profile_needs_rearm(&s.store, server)?;
        enable()?;
        if kernel::established_warm_client(&s.store, server)? {
            return run(s, Operation::Refresh, None);
        }
        if rearm {
            // A newly started daemon may need another handshake before its
            // committed selectors can forward. The ordinary worker retries.
            s.route_kernel.notify_rearm();
            if let Err(error) = run(s, Operation::Refresh, None) {
                s.logs.append("awg2", "warn", &error.to_string());
            }
        }
        Ok(())
    })
}

pub(crate) fn reorder_active_failover(
    s: &Shared,
    id: &str,
    change: &nfqws2_awg_profile::Failover,
) -> io::Result<bool> {
    let _guard = s
        .route_kernel
        .operations
        .lock()
        .map_err(|_| io::Error::other("менеджер маршрутов недоступен"))?;
    let staged = s.awg_runtime.stage_active_failover_order(
        &s.store,
        id,
        change,
        |before, after, retained| {
            kernel::stage_routed_failover_order(
                &s.store,
                &System,
                before,
                after,
                id,
                retained,
                |cfg, iface| routing_live_peer(s, cfg, iface),
            )
        },
    )?;
    if staged {
        publish_after(s, Operation::Refresh, || {
            kernel::finish_routed_failover_order(&s.store, &System, |cfg, iface| {
                routing_live_peer(s, cfg, iface)
            })
            .map(|_| ())
        })?;
    }
    Ok(staged)
}

pub(crate) fn retry_profiles<T: Default>(
    s: &Shared,
    apply: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let _guard = match s.route_kernel.operations.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return Ok(T::default()),
        Err(std::sync::TryLockError::Poisoned(_)) => {
            return Err(io::Error::other("менеджер маршрутов недоступен"))
        }
    };
    apply_profile(s, apply)
}

fn apply_profile<T>(s: &Shared, apply: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let result = apply();
    // The profile callback has released its guards. Live peer verification
    // can safely query the client manager again for the queued FIB update.
    let routes = kernel::pending_mtu_edit(&s.store).and_then(|pending| {
        if pending {
            run(s, Operation::Refresh, None)
        } else {
            Ok(())
        }
    });
    if let Err(error) = routes {
        s.logs.append("awg2", "warn", &error.to_string());
    }
    result
}
const DNS_PERIOD: Duration = Duration::from_secs(60);
const DNS_BUDGET: Duration = Duration::from_secs(8);
const LEGACY_WATCHDOG_PERIOD: Duration = Duration::from_secs(60);

fn legacy_watchdog_interval() -> Interval {
    let mut clock = time::interval_at(
        time::Instant::now() + LEGACY_WATCHDOG_PERIOD,
        LEGACY_WATCHDOG_PERIOD,
    );
    clock.set_missed_tick_behavior(MissedTickBehavior::Skip);
    clock
}

fn resolve_names(
    request: DnsRequest,
    servers: &[SocketAddr],
    deadline: Instant,
    lookup: impl Fn(&str, &[SocketAddr], Instant, bool, bool) -> io::Result<Vec<IpAddr>> + Sync,
) -> io::Result<DnsSnapshot> {
    let group = |names: &[String]| -> io::Result<BTreeMap<String, Vec<IpAddr>>> {
        let mut values = BTreeMap::new();
        for name in names {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let ipv6_only = request.ipv6_only.binary_search(name).is_ok();
            let ips = lookup(
                name,
                servers,
                deadline,
                !ipv6_only,
                ipv6_only || request.dual_stack.binary_search(name).is_ok(),
            )
            .map_err(|e| io::Error::new(e.kind(), format!("DNS {name}: {e}")))?;
            values.insert(name.clone(), ips);
        }
        Ok(values)
    };
    // One lookup runs on the existing blocking worker. Larger batches may
    // use one extra stack; both halves share the same wall-clock budget.
    let answers = if request.names.len() < 4 {
        group(&request.names)?
    } else {
        let (left, right) = request.names.split_at(request.names.len().div_ceil(2));
        std::thread::scope(|scope| -> io::Result<_> {
            let other = std::thread::Builder::new()
                .stack_size(192 * 1024)
                .spawn_scoped(scope, || group(right))?;
            let first = group(left);
            let second = other
                .join()
                .map_err(|_| io::Error::other("прерван выбор адресов DNS"))?;
            let mut answers = first?;
            answers.extend(second?);
            Ok(answers)
        })?
    };
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(DnsSnapshot { request, answers })
}
pub(crate) fn snapshot(s: &Shared, op: Operation) -> io::Result<Option<DnsSnapshot>> {
    Ok(prepare_snapshot(s, op, false)?.map(|prepared| prepared.snapshot))
}

struct PreparedDns {
    snapshot: DnsSnapshot,
    fresh: Option<FreshDns>,
    static_proof: Option<static_dns::Proof>,
}

enum DnsApplyProof<'a> {
    Fresh(&'a FreshDns),
    Static(&'a static_dns::Proof),
}

pub(super) struct FreshDns {
    failure: FreshFailure,
    origin: ManagedOriginReceipt,
    expires: Instant,
}

#[derive(Clone, Copy)]
enum FreshFailure {
    Scoped(FailedRoute),
    Compensated(observer::StaticApplyEpoch),
}

impl FreshFailure {
    fn current(self, s: &Shared) -> bool {
        match self {
            Self::Scoped(failure) => s.route_kernel.observer.same_failure(failure),
            Self::Compensated(epoch) => {
                s.route_kernel.observer.compensated_failure_epoch() == Some(epoch)
            }
        }
    }
}

impl FreshDns {
    fn resolver_current(s: &Shared, origin: &ManagedOriginReceipt) -> bool {
        s.dnsserver
            .archive_resolver()
            .is_some_and(|current| origin.same(&current))
    }

    fn preparing(s: &Shared, failure: FreshFailure, origin: &ManagedOriginReceipt) -> bool {
        failure.current(s) && Self::resolver_current(s, origin)
    }

    fn check_apply(&self, s: &Shared) -> io::Result<()> {
        if !self.failure.current(s) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.check_resolver(s)
    }

    pub(super) fn check_resolver(&self, s: &Shared) -> io::Result<()> {
        if Instant::now() >= self.expires {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if !Self::resolver_current(s, &self.origin) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

fn resolve_fresh(
    s: &Shared,
    request: DnsRequest,
    deadline: Instant,
    failure: FreshFailure,
    resolver: ArchiveResolver,
    scoped: Option<(SocketAddr, Vec<String>)>,
) -> io::Result<PreparedDns> {
    let origin = resolver
        .managed_origin_receipt()
        .ok_or(io::ErrorKind::Interrupted)?;
    let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
    let expiry = std::sync::Mutex::new(None::<Instant>);
    let listener = scoped.as_ref().map(|(listener, _)| *listener);
    let snapshot = resolve_names(
        request,
        listener.as_slice(),
        deadline,
        |name, servers, deadline, v4, v6| {
            if scoped.as_ref().is_some_and(|(_, blocked)| {
                blocked
                    .binary_search_by(|blocked| blocked.as_str().cmp(name))
                    .is_err()
            }) {
                return super::resolve::addresses(name, servers, deadline, v4, v6);
            }
            let (state, pinned, host, current_origin) =
                (s.clone(), resolver.clone(), name.to_owned(), origin.clone());
            // Keep async TLS polling on the runtime. The small snapshot
            // threads only wait for the result.
            let job = runtime.spawn(async move {
                Box::pin(super::resolve::managed_addresses(
                    &pinned,
                    &host,
                    deadline,
                    v4,
                    v6,
                    || FreshDns::preparing(&state, failure, &current_origin),
                ))
                .await
            });
            let (ips, expires) = runtime.block_on(job).map_err(io::Error::other)??;
            let mut expiry = expiry
                .lock()
                .map_err(|error| io::Error::other(error.to_string()))?;
            *expiry = Some(expiry.map_or(expires, |at| at.min(expires)));
            Ok(ips)
        },
    )?;
    let expires = expiry
        .into_inner()
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("нет свежего DNS-ответа для маршрута"))?;
    let fresh = FreshDns {
        failure,
        origin,
        expires,
    };
    fresh.check_apply(s)?;
    Ok(PreparedDns {
        snapshot,
        fresh: Some(fresh),
        static_proof: None,
    })
}

fn prepare_snapshot(s: &Shared, op: Operation, recover: bool) -> io::Result<Option<PreparedDns>> {
    let Some(request) = kernel::dns_request(&s.store, op)? else {
        return Ok(None);
    };
    prepare_requested_snapshot(s, op, recover, request).map(Some)
}

fn prepare_requested_snapshot(
    s: &Shared,
    op: Operation,
    recover: bool,
    request: DnsRequest,
) -> io::Result<PreparedDns> {
    let _permit = s.route_kernel.resolving.try_lock().map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "уже идёт обновление DNS-адресов маршрутов",
        )
    })?;
    let deadline = Instant::now() + DNS_BUDGET;
    let compensated = s.route_kernel.observer.compensated_failure_epoch();
    if recover && op == Operation::Apply {
        if compensated.is_none() {
            if let Some((failure, blocked)) =
                s.route_kernel.observer.blocked_static_names(&request.names)
            {
                if let Some((listener, resolver)) = s.dnsserver.routing_recovery_resolver()? {
                    return resolve_fresh(
                        s,
                        request,
                        deadline,
                        FreshFailure::Scoped(failure),
                        resolver,
                        Some((listener, blocked)),
                    );
                }
            }
        }
        if let Some(prepared) = static_dns::prepare(s, &request, deadline, compensated.is_some())? {
            let (snapshot, static_proof, fresh) = match prepared {
                static_dns::Prepared::Checked(proof) => {
                    (proof.snapshot().clone(), Some(proof), None)
                }
                static_dns::Prepared::Fresh {
                    snapshot,
                    expires,
                    origin,
                } => (
                    snapshot,
                    None,
                    compensated.map(|epoch| FreshDns {
                        failure: FreshFailure::Compensated(epoch),
                        origin,
                        expires,
                    }),
                ),
            };
            if let Some(fresh) = &fresh {
                fresh.check_apply(s)?;
            }
            return Ok(PreparedDns {
                snapshot,
                fresh,
                static_proof,
            });
        }
    }
    if matches!(op, Operation::Apply | Operation::Refresh) {
        if let Some(epoch) = compensated {
            if let Some((_, resolver)) = s.dnsserver.routing_recovery_resolver()? {
                return resolve_fresh(
                    s,
                    request,
                    deadline,
                    FreshFailure::Compensated(epoch),
                    resolver,
                    None,
                );
            }
        }
    }
    let servers = match s.dnsserver.routing_nameserver()? {
        Some(address) => vec![address],
        None => super::resolve::nameservers(&s.route_kernel.resolv_conf)?,
    };
    let snapshot = resolve_names(request, &servers, deadline, super::resolve::addresses)?;
    Ok(PreparedDns {
        snapshot,
        fresh: None,
        static_proof: None,
    })
}

fn run_dns_refresh(s: &Shared, prepared: &PreparedDns) -> io::Result<()> {
    let op = Operation::Refresh;
    let Some(fresh) = &prepared.fresh else {
        return run(s, op, Some(&prepared.snapshot));
    };
    finish_dns_refresh(s, fresh, || {
        let result = redirect::operate(
            s,
            op,
            Some(&prepared.snapshot),
            Some(DnsApplyProof::Fresh(fresh)),
        );
        let installed = result.is_ok()
            && kernel::installed_static_dns_snapshot(&s.store, &prepared.snapshot).unwrap_or(false);
        (result, installed)
    })
}

fn finish_dns_refresh(
    s: &Shared,
    fresh: &FreshDns,
    apply: impl FnOnce() -> (io::Result<()>, bool),
) -> io::Result<()> {
    let op = Operation::Refresh;
    fresh.check_apply(s)?;
    publish_after_classified(s, op, || {
        let (result, installed) = apply();
        let outcome = if result.is_ok() && installed && fresh.check_resolver(s).is_ok() {
            observer::PublicationOutcome::VerifiedStaticRefresh
        } else {
            observer::PublicationOutcome::from_result(op, &result)
        };
        (result, outcome)
    })
}
fn inspect(db: &nfqws2_store::Store) -> io::Result<Value> {
    let s = kernel::inspect(db, &System)?;
    Ok(serde_json::json!({"ready":s.ready,"active":s.active,"pending_commit":s.pending_commit}))
}
async fn worker(s: &Shared) -> watch::Sender<usize> {
    let mut slot = s.route_kernel.worker.lock().await;
    if let Some((tx, _)) = &*slot {
        return tx.clone();
    }
    let (tx, mut signal) = watch::channel(s.route_kernel.generation.load(Ordering::Acquire));
    let weak = Arc::downgrade(s);
    let job = tokio::spawn(async move {
        let mut last = String::new();
        let mut next_dns = Instant::now() + DNS_PERIOD;
        let mut next_sources = Instant::now();
        let mut legacy_clock = None;
        let mut fw4 = fw4_events::Watch::default();
        let mut last_fw4_error = String::new();
        'schedule: loop {
            let generation = *signal.borrow_and_update();
            let Some(state) = weak.upgrade() else {
                return;
            };
            let store = state.store.clone();
            drop(state);
            let timer =
                tokio::task::spawn_blocking(move || kernel::schedule_with_fw4_chain(&store))
                    .await
                    .ok()
                    .and_then(Result::ok);
            fw4.enable(timer.as_ref().and_then(|(_, chain)| chain.as_deref()));
            let timer = timer.map(|(schedule, _)| schedule);
            let auditing = matches!(timer, Some(Schedule::Audit));
            let dns = matches!(timer, Some(Schedule::Dns));
            let failover = dns || matches!(timer, Some(Schedule::Failover));
            let watchdog = matches!(timer, Some(Schedule::LegacyWatchdog));
            if watchdog {
                legacy_clock.get_or_insert_with(legacy_watchdog_interval);
            } else {
                legacy_clock = None;
            }
            let seconds = match timer {
                Some(Schedule::Restore) => 10,
                Some(Schedule::Expires(end)) => {
                    end.saturating_sub(nfqws2_awg_profile::now()).min(90)
                }
                Some(Schedule::Fw3Trial(end)) => {
                    end.saturating_sub(nfqws2_awg_profile::now()).min(10)
                }
                Some(Schedule::Audit | Schedule::LegacyWatchdog) => 60,
                Some(Schedule::Failover | Schedule::Dns) => 30,
                Some(Schedule::Idle) => {
                    if signal.changed().await.is_err() {
                        return;
                    }
                    continue;
                }
                _ => 30,
            };
            let deadline = async {
                if let Some(clock) = &mut legacy_clock {
                    clock.tick().await;
                } else {
                    time::sleep(Duration::from_secs(seconds)).await;
                }
            };
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    biased;
                    result = signal.changed() => { if result.is_err() {return;} continue 'schedule; }
                    _ = &mut deadline => break,
                    _ = fw4.changed() => {
                        let Some(state) = weak.upgrade() else {return;};
                        let s = state.clone();
                        match tokio::task::spawn_blocking(move || {
                            lifecycle_operation(&s, Operation::FirewallReload)?;
                            kernel::schedule_with_fw4_chain(&s.store)
                        }).await {
                            Ok(Err(e)) if last_fw4_error != e.to_string() => {
                                last_fw4_error=e.to_string();
                                state.logs.append("awg2", "warn", &last_fw4_error);
                            }
                            Ok(Ok((_, chain))) => {
                                fw4.enable(chain.as_deref());
                                last_fw4_error.clear();
                            }
                            _ => (),
                        }
                    }
                }
            }
            let Some(state) = weak.upgrade() else {
                return;
            };
            let s = state.clone();
            let refresh_dns = dns && Instant::now() >= next_dns;
            let refresh_sources = (auditing || failover) && Instant::now() >= next_sources;
            if refresh_sources {
                next_sources = Instant::now() + Duration::from_secs(15 * 60);
            }
            if refresh_dns {
                next_dns = Instant::now() + DNS_PERIOD;
            }
            // A simultaneous commit/second apply cancels the expired trial.
            // Recheck the generation under the same lock as mutations.
            let result = tokio::task::spawn_blocking(move || {
                let pending_dns = if matches!(timer, Some(Schedule::Restore)) {
                    prepare_pending_replacement_dns(&s)
                } else {
                    Ok(None)
                };
                let pending_rotation = if matches!(timer, Some(Schedule::Restore)) {
                    kernel::prepare_deferred_named_rotation(&s.store, |row, iface| {
                        routing_live_peer(&s, row, iface)
                    })
                } else {
                    Ok(None)
                };
                let answers = if refresh_dns {
                    prepare_snapshot(&s, Operation::Refresh, false)
                } else {
                    Ok(None)
                };
                let operations = &s.route_kernel.operations;
                let unavailable = || io::Error::other("менеджер маршрутов недоступен");
                let _guard = if watchdog {
                    match operations.try_lock() {
                        Ok(guard) => guard,
                        Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
                        Err(std::sync::TryLockError::Poisoned(_)) => return Err(unavailable()),
                    }
                } else {
                    operations.lock().map_err(|_| unavailable())?
                };
                if s.route_kernel
                    .generation
                    .load(std::sync::atomic::Ordering::Acquire)
                    != generation
                {
                    return Ok(());
                }
                match pending_dns {
                    Ok(Some(proof)) => {
                        let result = publish_after(&s, Operation::Recover, || {
                            redirect::prepare_active_replacement(&s, proof.bridges())?;
                            kernel::resume_active_replacement_dns_retry(
                                &s.store,
                                &System,
                                &proof,
                                |row, iface| routing_live_peer(&s, row, iface),
                            )
                        });
                        return finish_dns_recovery(&s, _guard, result);
                    }
                    Err(error) => {
                        let result = run(&s, Operation::Recover, None);
                        return finish_dns_recovery(&s, _guard, result).and(Err(error));
                    }
                    Ok(None) => {}
                }
                match pending_rotation {
                    Ok(Some(proof)) => {
                        let result = publish_after(&s, Operation::Recover, || {
                            kernel::resume_deferred_named_rotation(
                                &s.store,
                                &System,
                                &proof,
                                s.config.awg_wan_ifaces(),
                                |row, iface| routing_live_peer(&s, row, iface),
                            )
                        });
                        return finish_dns_recovery(&s, _guard, result);
                    }
                    Err(error) => {
                        let result = run(&s, Operation::Recover, None);
                        return finish_dns_recovery(&s, _guard, result).and(Err(error));
                    }
                    Ok(None) => {}
                }
                if watchdog {
                    let result = run(&s, Operation::LegacyWatchdog, None);
                    return finish_dns_recovery(&s, _guard, result);
                }
                if matches!(timer, Some(Schedule::Fw3Trial(end)) if end > nfqws2_awg_profile::now())
                {
                    let result = run(&s, Operation::Refresh, None);
                    return finish_dns_recovery(&s, _guard, result);
                }
                let sources = if refresh_sources && kernel::has_local_sources(&s.store)? {
                    super::stage_sources(&s.config, &s.store)
                        .and_then(|_| kernel::local_sources_changed(&s.store))
                } else {
                    Ok(false)
                };
                if matches!(sources, Ok(true)) {
                    let snapshot = snapshot(&s, Operation::ReloadSources)?;
                    run(&s, Operation::ReloadSources, snapshot.as_ref())?;
                    let publication = s.route_kernel.observer.replay_publication();
                    drop(_guard);
                    if let Some(publication) = publication {
                        s.dnsserver.replay_recent_routes(publication);
                    }
                    return Ok(());
                }
                if auditing && kernel::inspect(&s.store, &System)?.active {
                    return sources.map(|_| ());
                }
                let op = if failover {
                    Operation::Refresh
                } else {
                    Operation::Recover
                };
                let routing = match answers {
                    Ok(Some(prepared)) => run_dns_refresh(&s, &prepared).or_else(|e| {
                        run(&s, Operation::Refresh, None)?;
                        Err(e)
                    }),
                    Ok(None) => run(&s, op, None),
                    Err(e) => {
                        // A DNS outage must not prevent the existing prefixes
                        // from switching to a live reserve or their kill switch.
                        run(&s, Operation::Refresh, None)?;
                        Err(e)
                    }
                };
                finish_dns_recovery(&s, _guard, routing).and(sources.map(|_| ()))
            })
            .await;
            match result {
                Ok(Err(e)) if last != e.to_string() => {
                    last = e.to_string();
                    state.logs.append("awg2", "warn", &last);
                }
                Ok(Ok(())) => last.clear(),
                _ => (),
            }
            if !last.is_empty() {
                tokio::select! {_=tokio::time::sleep(Duration::from_secs(5))=>(),r=signal.changed()=>{if r.is_err(){return;}}}
            }
        }
    });
    *slot = Some((tx.clone(), job));
    tx
}
async fn command(s: Shared, op: Operation) -> Result<Json<Value>, ApiError> {
    let wake = worker(&s).await;
    task(move || {
        let generation = s.route_kernel.generation.load(Ordering::Acquire);
        if matches!(op, Operation::Apply | Operation::Commit) {
            super::stage_sources(&s.config, &s.store)?;
        }
        let answers = if op == Operation::Apply {
            prepare_snapshot(&s, op, true)?
        } else {
            None
        };
        let _guard = s
            .route_kernel
            .operations
            .lock()
            .map_err(|_| io::Error::other("менеджер маршрутов недоступен"))?;
        if answers.is_some() && generation != s.route_kernel.generation.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "маршруты изменились во время запроса DNS, повторите применение",
            ));
        }
        let snapshot = answers.as_ref().map(|prepared| &prepared.snapshot);
        let static_proof = answers.as_ref().and_then(|dns| dns.static_proof.as_ref());
        let legacy_commit =
            op == Operation::Commit && kernel::bare_full_commit_uses_go_response(&s.store)?;
        let result = if let Some(proof) = static_proof {
            proof.check_apply(&s)?;
            publish_after(&s, op, || {
                redirect::operate(&s, op, snapshot, Some(DnsApplyProof::Static(proof)))
            })
        } else if let Some(fresh) = answers.as_ref().and_then(|dns| dns.fresh.as_ref()) {
            fresh.check_apply(&s)?;
            publish_after(&s, op, || {
                redirect::operate(&s, op, snapshot, Some(DnsApplyProof::Fresh(fresh)))
            })
        } else {
            run(&s, op, snapshot)
        };
        let gen = s
            .route_kernel
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        static_dns::finish(&s, static_proof, gen, &result);
        wake.send_replace(gen);
        result?;
        let publication = if matches!(op, Operation::Apply | Operation::Commit) {
            s.route_kernel.observer.replay_publication()
        } else {
            None
        };
        let response = if legacy_commit {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "маршрутизация не активна",
            ))
        } else if op == Operation::Commit {
            Ok(serde_json::json!({"status":"committed"}))
        } else {
            status(&s)
        };
        drop(_guard);
        if let Some(publication) = publication {
            s.dnsserver.replay_recent_routes(publication);
        }
        response
    })
    .await
}

#[cfg(test)]
pub(crate) fn install_route_observer_for_test(s: &Shared) {
    s.dnsserver
        .set_route_observer(Arc::new(observer::Hook(Arc::downgrade(s))));
}

#[cfg(test)]
pub(crate) enum DnsPublicationFixture {
    Ready,
    Compensated,
    Unreadable,
}

#[cfg(test)]
pub(crate) fn hold_dns_operation_for_test(
    s: &Shared,
    op: Operation,
) -> impl FnOnce(DnsPublicationFixture) -> io::Result<()> {
    s.route_kernel.observer.begin(op).unwrap();
    let s = s.clone();
    move |completion| {
        let (active, outcome) = match completion {
            DnsPublicationFixture::Ready => (Ok(None), observer::PublicationOutcome::Succeeded(op)),
            DnsPublicationFixture::Compensated => {
                (Ok(None), observer::PublicationOutcome::CompensatedStatic)
            }
            DnsPublicationFixture::Unreadable => (
                Err(io::Error::other("fixture unreadable route observation")),
                observer::PublicationOutcome::Failed,
            ),
        };
        s.route_kernel.observer.publish_write(active, outcome)
    }
}

#[cfg(test)]
pub(crate) fn waiting_dns_queries_for_test(s: &Shared) -> usize {
    s.route_kernel.observer.waiting_dns_queries()
}

#[cfg(test)]
pub(crate) fn publish_dns_operation_for_test(s: &Shared, op: Operation) -> io::Result<()> {
    let _guard = s.route_kernel.operations.lock().unwrap();
    publish_after(s, op, || Ok(()))
}

#[cfg(test)]
pub(crate) fn refresh_static_dns_for_test(
    s: &Shared,
    request: DnsRequest,
    apply: impl FnOnce(&DnsSnapshot, Instant) -> (io::Result<()>, bool),
) -> io::Result<()> {
    let prepared = prepare_requested_snapshot(s, Operation::Refresh, false, request)?;
    let fresh = prepared.fresh.as_ref().ok_or(io::ErrorKind::NotFound)?;
    let _guard = s.route_kernel.operations.lock().unwrap();
    finish_dns_refresh(s, fresh, || apply(&prepared.snapshot, fresh.expires))
}

#[cfg(test)]
pub(crate) fn publish_failed_dns_for_test(
    s: &Shared,
    policy: nfqws2_awg_rules::observed::Policy,
) -> io::Result<()> {
    install_route_observer_for_test(s);
    s.route_kernel.observer.begin(Operation::Apply)?;
    s.route_kernel.observer.publish(
        Ok(Some(kernel::Observation {
            policy,
            revision: 7,
            ready: false,
            trial_expires: 0,
            block_aaaa: Vec::new(),
            go_ipv4: false,
        })),
        true,
    )
}

#[cfg(test)]
pub(crate) fn prepare_failed_apply_for_test(
    s: &Shared,
) -> io::Result<(DnsSnapshot, Instant, impl Fn(&Shared) -> io::Result<()>)> {
    let prepared = prepare_snapshot(s, Operation::Apply, true)?
        .ok_or_else(|| io::Error::other("нет снимка DNS"))?;
    let fresh = prepared
        .fresh
        .ok_or_else(|| io::Error::other("нет свежего DNS-ответа"))?;
    Ok((prepared.snapshot, fresh.expires, move |s: &Shared| {
        fresh.check_apply(s)
    }))
}
async fn apply(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    command(s, Operation::Apply).await
}
async fn teardown(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    command(s, Operation::Teardown).await
}
async fn commit(State(s): State<Shared>) -> Result<Json<Value>, ApiError> {
    command(s, Operation::Commit).await
}
/// The installer confirms the trial only after checking DNS, the panel and
/// a routed destination. Ordinary boots recover the durable native receipt.
pub async fn start_go_handoff(s: &Shared) {
    match kernel::handoff::pending(&s.store) {
        Ok(false) => {}
        Ok(true) => {
            if let Err(error) = command(s.clone(), Operation::Apply).await {
                s.logs.append("awg2", "error", &error.1);
            }
            // Covers failures before the kernel transaction (e.g. DNS).
            if let Err(error) = kernel::handoff::cancel(&s.store) {
                s.logs.append("awg2", "warn", &error.to_string());
            }
        }
        Err(error) => s.logs.append("awg2", "error", &error.to_string()),
    }
}
pub async fn restore(s: &Shared) {
    s.dnsserver
        .set_route_observer(Arc::new(observer::Hook(Arc::downgrade(s))));
    s.awg_runtime.register_routing(inspect);
    let state = s.clone();
    if let Ok(Err(e)) =
        tokio::task::spawn_blocking(move || lifecycle_operation(&state, Operation::Recover)).await
    {
        s.logs.append("awg2", "warn", &e.to_string());
    }
    worker(s).await;
}
pub async fn shutdown(s: &Shared) {
    let job = s.route_kernel.worker.lock().await.take();
    if let Some((tx, job)) = job {
        drop(tx);
        let _ = job.await;
    }
    let state = s.clone();
    if let Ok(Err(e)) =
        tokio::task::spawn_blocking(move || lifecycle_operation(&state, Operation::Suspend)).await
    {
        s.logs.append("awg2", "warn", &e.to_string());
    }
}

fn lifecycle_operation(s: &Shared, op: Operation) -> io::Result<()> {
    let _guard = s
        .route_kernel
        .operations
        .lock()
        .map_err(|_| io::Error::other("менеджер маршрутов недоступен"))?;
    let result = run(s, op, None);
    if op == Operation::Recover {
        return finish_dns_recovery(s, _guard, result);
    }
    if op == Operation::Suspend && result.is_ok() {
        if let Err(error) = crate::awg_profiles::finish_active_replacement_retirement(s) {
            s.logs.append("awg2", "warn", &error.to_string());
        }
    }
    result
}

fn finish_dns_recovery(
    s: &Shared,
    guard: std::sync::MutexGuard<'_, ()>,
    result: io::Result<()>,
) -> io::Result<()> {
    if result.is_ok() {
        if let Err(error) = crate::awg_profiles::finish_active_replacement_retirement(s) {
            s.logs.append("awg2", "warn", &error.to_string());
        }
    }
    let publication = result
        .as_ref()
        .ok()
        .and_then(|_| s.route_kernel.observer.replay_publication());
    drop(guard);
    if let Some(publication) = publication {
        s.dnsserver.replay_restored_routes(publication);
    }
    result
}

#[cfg(test)]
mod tests;
