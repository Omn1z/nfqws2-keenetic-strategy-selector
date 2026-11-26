use crate::{
    dnsserver::{
        ArchiveResolver, DeliverySelection, DnsOrigin, FailedRoute, RedirectEpoch, RouteAnswer,
        RouteMatch, RouteObserver, RoutePublication, RouteWriterBusy, WarmDnsObservation,
    },
    http::AppState,
};
use nfqws2_awg_rules::kernel::{self, Answer, ArchiveAnswer, Observation};
use nfqws2_router_command::System;
use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::{RwLock, TryLockError, Weak},
    time::{Duration, Instant},
};
use tokio::sync::watch;

#[derive(Default)]
pub(super) struct Gate(RwLock<State>, watch::Sender<()>);
#[derive(Default)]
struct State {
    epoch: u64,
    generation: u64,
    redirect_replacement: u64,
    last_failure: Option<u64>,
    compensated_failure: bool,
    updating: Update,
    active: Option<Observation>,
    hits: VecDeque<Hit>,
}
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum Update {
    #[default]
    Idle,
    Refresh,
    Replace,
    Unavailable,
}

impl Update {
    fn applying(self) -> bool {
        matches!(self, Self::Refresh | Self::Replace)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct StaticApplyEpoch {
    epoch: u64,
    generation: u64,
}

pub(super) enum PublicationOutcome {
    Succeeded(kernel::Operation),
    VerifiedStaticRefresh,
    Failed,
    CompensatedStatic,
}

impl PublicationOutcome {
    pub(super) fn from_result(op: kernel::Operation, result: &io::Result<()>) -> Self {
        match result {
            Ok(()) => Self::Succeeded(op),
            Err(error)
                if op == kernel::Operation::Apply
                    && kernel::failed_static_dns_apply(error).is_some() =>
            {
                Self::CompensatedStatic
            }
            Err(_) => Self::Failed,
        }
    }
}
struct Hit {
    zone: usize,
    name: String,
    client: Option<IpAddr>,
    ingress: Option<String>,
    qtype: u16,
    ips: Vec<IpAddr>,
    accepted: Vec<IpAddr>,
    until: Instant,
    ttl: u32,
    suppress: bool,
}
impl State {
    fn confirmed_firmware_publication(&self) -> Option<RoutePublication> {
        let active = self.active.as_ref()?;
        if self.last_failure.is_some()
            || active.trial_expires != 0
            || active.policy.uses_legacy_full()
        {
            return None;
        }
        self.replay_publication()
    }

    fn firmware_hint_publication(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> Option<RoutePublication> {
        origin.ingress?;
        let publication = self.confirmed_firmware_publication()?;
        let active = self.active.as_ref()?;
        if !(active.policy.matched(name, None) == Some(target.zone)
            || origin
                .client
                .is_some_and(|client| active.policy.matches_single_client(target.zone, client)))
            || active.policy.history_match(target.zone, name).is_none()
            || self.select(name, origin).ok().flatten() != Some(target)
        {
            return None;
        }
        Some(publication)
    }

    fn replay_publication(&self) -> Option<RoutePublication> {
        let active = self.active.as_ref()?;
        (self.updating == Update::Idle && active.ready).then_some(RoutePublication {
            generation: self.generation,
            revision: active.revision,
        })
    }

    fn archive_matches(
        &self,
        publication: RoutePublication,
        name: &str,
        qtype: u16,
    ) -> io::Result<bool> {
        if self.replay_publication() != Some(publication) {
            return Err(unavailable());
        }
        let active = self.active.as_ref().ok_or_else(unavailable)?;
        if active.trial_expires != 0 && nfqws2_awg_profile::now() >= active.trial_expires {
            return Err(unavailable());
        }
        Ok(!(qtype == 28 && active.go_ipv4)
            && active.policy.archive_zones(name, qtype).next().is_some())
    }

    fn failed_native(&self) -> Option<(&Observation, FailedRoute)> {
        if self.updating != Update::Idle || self.last_failure != Some(self.epoch) {
            return None;
        }
        let active = self.active.as_ref()?;
        if active.ready
            || active.policy.uses_legacy_full()
            || active.trial_expires != 0 && nfqws2_awg_profile::now() >= active.trial_expires
        {
            return None;
        }
        Some((
            active,
            FailedRoute {
                epoch: self.epoch,
                generation: self.generation,
            },
        ))
    }

    fn failed_route(&self, name: &str, origin: DnsOrigin<'_>) -> Option<FailedRoute> {
        if origin.ingress.is_some() {
            return None;
        }
        let client = origin.client.filter(|client| !client.is_loopback())?;
        let (active, failure) = self.failed_native()?;
        let zone = active.policy.matched(name, Some(client))?;
        active.policy.history_match(zone, name)?;
        Some(failure)
    }

    fn recovered(&self, publication: RoutePublication, failure: FailedRoute) -> bool {
        self.last_failure.is_none()
            && publication.generation != failure.generation
            && self.replay_publication() == Some(publication)
    }

    fn matched(&self, name: &str, origin: DnsOrigin<'_>) -> Option<(&Observation, usize)> {
        let policy = self.active.as_ref()?;
        let client = origin
            .client
            .filter(|&client| policy.legacy_accepts_peer(client, origin.ingress));
        Some((policy, policy.policy.matched(name, client)?))
    }

    fn redirect_epoch(&self, name: &str, origin: DnsOrigin<'_>) -> RedirectEpoch {
        let matched = self.matched(name, origin);
        RedirectEpoch {
            replacement: self.redirect_replacement,
            revision: self.active.as_ref().map(|active| active.revision),
            zone: matched.map(|(_, zone)| zone),
            suppress_aaaa: matched
                .is_some_and(|(active, zone)| active.block_aaaa.binary_search(&zone).is_ok()),
            unavailable: matches!(self.updating, Update::Replace | Update::Unavailable),
        }
    }

    fn select(&self, name: &str, origin: DnsOrigin<'_>) -> io::Result<Option<RouteMatch>> {
        if matches!(self.updating, Update::Replace | Update::Unavailable) {
            return Err(unavailable());
        }
        let Some((policy, zone)) = self.matched(name, origin) else {
            return Ok(None);
        };
        if self.updating == Update::Refresh
            || !policy.ready
            || policy.trial_expires != 0 && nfqws2_awg_profile::now() >= policy.trial_expires
        {
            return Err(self
                .failed_route(name, origin)
                .map_or_else(unavailable, io::Error::other));
        }
        Ok(Some(RouteMatch {
            revision: self.epoch,
            generation: self.generation,
            zone,
        }))
    }
    fn select_managed(&self, name: &str, origin: DnsOrigin<'_>) -> io::Result<Option<RouteMatch>> {
        if self.compensated_failure {
            return Err(io::Error::other("политика DNS-маршрутизации не готова"));
        }
        if self.updating.applying() {
            return Err(unavailable());
        }
        self.select(name, origin)
    }
    fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.hits.clear();
    }
    fn cached(
        &self,
        s: &AppState,
        zone: usize,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
        observed: bool,
    ) -> Option<bool> {
        let hit = self.hits.iter().find(|h| {
            h.zone == zone
                && h.name == name
                && h.client == origin.client
                && h.ingress.as_deref() == origin.ingress
                && h.qtype == answer.qtype
                && h.ips == answer.addresses
                && h.ttl >= answer.ttl
                && h.until > Instant::now()
        })?;
        if observed {
            self.confirm(s, zone, name, origin.client, &hit.accepted);
        }
        Some(hit.suppress)
    }
    fn confirm(
        &self,
        s: &AppState,
        zone: usize,
        name: &str,
        client: Option<IpAddr>,
        ips: &[IpAddr],
    ) {
        if let Some(active) = &self.active {
            if let Some(rule) = active
                .policy
                .history_match(zone, name)
                .filter(|_| !ips.is_empty())
            {
                s.dnsserver
                    .confirm_routing(active.revision, rule, name, client, ips);
            }
        }
    }
}
fn unavailable() -> io::Error {
    io::Error::other("обновляется политика DNS-маршрутизации")
}
fn archived_resolver(s: &AppState, active: &Observation) -> Option<ArchiveResolver> {
    if active.policy.uses_legacy_full() {
        return None;
    }
    s.dnsserver.archive_resolver()
}
impl Gate {
    pub(super) fn confirmed_firmware_publication(&self) -> Option<RoutePublication> {
        self.0.read().ok()?.confirmed_firmware_publication()
    }
    pub(super) fn compensated_failure_epoch(&self) -> Option<StaticApplyEpoch> {
        let state = self.0.try_read().ok()?;
        (state.updating == Update::Idle && state.compensated_failure).then_some(StaticApplyEpoch {
            epoch: state.epoch,
            generation: state.generation,
        })
    }

    pub(super) fn idle_static_epoch(&self, failed: bool) -> Option<StaticApplyEpoch> {
        let state = self.0.try_read().ok()?;
        (state.updating == Update::Idle
            && state.active.is_none()
            && (!failed || state.last_failure == Some(state.epoch)))
        .then_some(StaticApplyEpoch {
            epoch: state.epoch,
            generation: state.generation,
        })
    }

    pub(super) fn started_static_apply(&self, previous: StaticApplyEpoch) -> bool {
        self.0.try_read().is_ok_and(|state| {
            state.updating == Update::Replace
                && state.active.is_none()
                && state.epoch == previous.epoch.wrapping_add(1)
                && state.generation == previous.generation
        })
    }

    pub(super) fn failure_epoch(&self) -> Option<u64> {
        self.0.read().ok()?.last_failure
    }

    pub(super) fn named_transport_failure(&self) -> Option<FailedRoute> {
        let state = self.0.try_read().ok()?;
        (state.updating == Update::Idle && state.last_failure == Some(state.epoch)).then_some(FailedRoute {
            epoch: state.epoch,
            generation: state.generation,
        })
    }

    pub(super) fn replay_publication(&self) -> Option<RoutePublication> {
        self.0.read().ok()?.replay_publication()
    }

    pub(super) fn blocked_static_names(
        &self,
        names: &[String],
    ) -> Option<(FailedRoute, Vec<String>)> {
        let state = self.0.read().ok()?;
        let (active, failure) = state.failed_native()?;
        let blocked: Vec<_> = names
            .iter()
            .filter(|name| {
                active
                    .policy
                    .matched(name, None)
                    .is_some_and(|zone| active.policy.history_match(zone, name).is_some())
            })
            .cloned()
            .collect();
        (!blocked.is_empty()).then_some((failure, blocked))
    }

    pub(super) fn same_failure(&self, failure: FailedRoute) -> bool {
        self.0.read().is_ok_and(|state| {
            state
                .failed_native()
                .is_some_and(|(_, current)| failure == current)
        })
    }

    pub fn begin(&self, op: kernel::Operation) -> io::Result<()> {
        let mut state = self.0.write().map_err(|_| unavailable())?;
        // A scheduled refresh keeps the same redirect policy. A replacement
        // invalidates the snapshots already held by firmware requests.
        state.updating = if matches!(
            op,
            kernel::Operation::Refresh | kernel::Operation::FirewallReload
        ) && state.updating == Update::Idle
        {
            Update::Refresh
        } else {
            Update::Replace
        };
        state.invalidate();
        if state.updating == Update::Replace {
            state.redirect_replacement = state.redirect_replacement.wrapping_add(1);
            self.1.send_replace(());
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn publish(
        &self,
        active: io::Result<Option<Observation>>,
        operation_failed: bool,
    ) -> io::Result<()> {
        self.publish_write(
            active,
            if operation_failed {
                PublicationOutcome::Failed
            } else {
                PublicationOutcome::Succeeded(kernel::Operation::Refresh)
            },
        )
    }

    pub(super) fn publish_write(
        &self,
        active: io::Result<Option<Observation>>,
        outcome: PublicationOutcome,
    ) -> io::Result<()> {
        let mut state = self.0.write().map_err(|_| unavailable())?;
        state.updating = Update::Unavailable;
        let success = matches!(
            outcome,
            PublicationOutcome::Succeeded(_) | PublicationOutcome::VerifiedStaticRefresh
        );
        state.last_failure = (!success || active.is_err()).then_some(state.epoch);
        match outcome {
            PublicationOutcome::CompensatedStatic => state.compensated_failure = true,
            PublicationOutcome::VerifiedStaticRefresh if active.is_ok() => {
                state.compensated_failure = false;
            }
            PublicationOutcome::Succeeded(op)
                if active.as_ref().is_ok_and(|active| {
                    matches!(op, kernel::Operation::Apply | kernel::Operation::Teardown)
                        || active.as_ref().is_some_and(|policy| policy.ready)
                }) =>
            {
                state.compensated_failure = false;
            }
            _ => (),
        }
        let result = active.map(|active| {
            state.active = active;
            state.generation = state.generation.wrapping_add(1);
            state.updating = Update::Idle;
        });
        drop(state);
        self.1.send_replace(());
        result
    }

    #[cfg(test)]
    pub(super) fn waiting_dns_queries(&self) -> usize {
        self.1.receiver_count()
    }
}
pub(super) struct Hook(pub Weak<AppState>);
impl RouteObserver for Hook {
    fn capture_warm_transport(&self, name: &str) -> Option<FailedRoute> {
        super::warm_named::capture(&self.0.upgrade()?, name)
    }

    fn observe_warm_transport(&self, observation: WarmDnsObservation<'_>) {
        if let Some(s) = self.0.upgrade() {
            super::warm_named::observe(&s, observation);
        }
    }
    fn blocks_aaaa(&self, target: RouteMatch) -> io::Result<bool> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let state = s
            .route_kernel
            .observer
            .0
            .read()
            .map_err(|_| unavailable())?;
        if state.updating != Update::Idle
            || state.epoch != target.revision
            || state.generation != target.generation
        {
            return Err(unavailable());
        }
        Ok(state
            .active
            .as_ref()
            .is_some_and(|p| p.block_aaaa.binary_search(&target.zone).is_ok()))
    }

    fn record_reply(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
        target: Option<RouteMatch>,
        reply: &[u8],
        suppressed: bool,
    ) {
        let Some(s) = self.0.upgrade() else { return };
        let Ok(state) = s.route_kernel.observer.0.read() else {
            return;
        };
        let Some(active) = &state.active else { return };
        if matches!(state.updating, Update::Replace | Update::Unavailable)
            || state.updating == Update::Refresh && target.is_some()
            || !active.ready
            || active.trial_expires != 0 && nfqws2_awg_profile::now() >= active.trial_expires
            || state.select(name, origin).ok() != Some(target)
        {
            return;
        }
        let Ok(answer) = nfqws2_dns::trace_answer(reply) else {
            return;
        };
        s.trace
            .awg
            .record_dns(name, origin.client, &answer, suppressed, |address| {
                let Some(zone) = target.map(|matched| matched.zone) else {
                    return (active.policy.trace_default(), None);
                };
                let decision = active
                    .policy
                    .trace_decision(zone, address)
                    .unwrap_or("direct");
                (decision, (decision != "cdn-skip").then_some(zone + 1))
            });
    }

    fn cached(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
    ) -> io::Result<Option<bool>> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let state = s
            .route_kernel
            .observer
            .0
            .read()
            .map_err(|_| unavailable())?;
        if state.updating != Update::Idle
            || state.epoch != target.revision
            || state.generation != target.generation
        {
            return Err(unavailable());
        }
        Ok(state.cached(&s, target.zone, name, origin, answer, true))
    }
    fn select(&self, name: &str, client: Option<IpAddr>) -> io::Result<Option<RouteMatch>> {
        self.select_on(
            name,
            DnsOrigin {
                client,
                ingress: None,
            },
        )
    }
    fn select_on(&self, name: &str, origin: DnsOrigin<'_>) -> io::Result<Option<RouteMatch>> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let state = s
            .route_kernel
            .observer
            .0
            .read()
            .map_err(|_| unavailable())?;
        state.select(name, origin)
    }

    fn select_managed_on(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> io::Result<Option<RouteMatch>> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let state = s
            .route_kernel
            .observer
            .0
            .read()
            .map_err(|_| unavailable())?;
        state.select_managed(name, origin)
    }

    fn select_managed_for_delivery(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> io::Result<DeliverySelection> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let gate = &s.route_kernel.observer;
        let state = gate.0.read().map_err(|_| unavailable())?;
        if state.updating.applying() {
            // Subscribe before releasing the snapshot so a completion cannot
            // be missed between the state check and the async wait.
            return Ok(DeliverySelection::Pending(gate.1.subscribe()));
        }
        state
            .select_managed(name, origin)
            .map(DeliverySelection::Ready)
    }

    fn capture_redirect(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> (Option<RedirectEpoch>, io::Result<Option<RouteMatch>>) {
        let Some(s) = self.0.upgrade() else {
            return (None, Err(unavailable()));
        };
        let Ok(state) = s.route_kernel.observer.0.read() else {
            return (None, Err(unavailable()));
        };
        (
            Some(state.redirect_epoch(name, origin)),
            state.select(name, origin),
        )
    }

    fn select_redirect_for_delivery(
        &self,
        name: &str,
        origin: DnsOrigin<'_>,
        epoch: RedirectEpoch,
    ) -> io::Result<DeliverySelection> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let gate = &s.route_kernel.observer;
        let state = gate.0.read().map_err(|_| unavailable())?;
        // A query admitted while the writer was unavailable cannot acquire
        // new authority later, even if its original domain still matches.
        if epoch.unavailable || state.redirect_epoch(name, origin) != epoch {
            return Err(unavailable());
        }
        if state.updating == Update::Refresh {
            return Ok(DeliverySelection::Pending(gate.1.subscribe()));
        }
        if state.last_failure.is_some() {
            return Err(unavailable());
        }
        state.select(name, origin).map(DeliverySelection::Ready)
    }

    fn replay_publication(&self) -> Option<RoutePublication> {
        self.0.upgrade()?.route_kernel.observer.replay_publication()
    }

    fn firmware_hint_publication(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> Option<RoutePublication> {
        let s = self.0.upgrade()?;
        let state = s.route_kernel.observer.0.read().ok()?;
        state.firmware_hint_publication(target, name, origin)
    }

    fn mixed_firmware_policy(&self, publication: RoutePublication) -> bool {
        self.0.upgrade().is_some_and(|s| {
            s.route_kernel.observer.0.read().is_ok_and(|state| {
                state.confirmed_firmware_publication() == Some(publication)
                    && state
                        .active
                        .as_ref()
                        .is_some_and(|active| active.policy.mixed_firmware_sources())
            })
        })
    }

    fn archive_resolver(&self, publication: RoutePublication) -> Option<ArchiveResolver> {
        let s = self.0.upgrade()?;
        let state = s.route_kernel.observer.0.read().ok()?;
        if state.replay_publication() != Some(publication) {
            return None;
        }
        archived_resolver(&s, state.active.as_ref()?)
    }

    fn failed_reply_current(
        &self,
        failure: FailedRoute,
        name: &str,
        origin: DnsOrigin<'_>,
        resolver: &ArchiveResolver,
    ) -> bool {
        let Some(s) = self.0.upgrade() else {
            return false;
        };
        let Ok(state) = s.route_kernel.observer.0.read() else {
            return false;
        };
        state.failed_route(name, origin) == Some(failure)
            && s.dnsserver
                .archive_resolver()
                .is_some_and(|current| resolver.same(&current))
    }

    fn recovered(&self, publication: RoutePublication, failure: FailedRoute) -> bool {
        let Some(s) = self.0.upgrade() else {
            return false;
        };
        let Ok(state) = s.route_kernel.observer.0.read() else {
            return false;
        };
        state.recovered(publication, failure)
    }

    fn replay_target(
        &self,
        publication: RoutePublication,
        name: &str,
        origin: DnsOrigin<'_>,
    ) -> io::Result<Option<RouteMatch>> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let state = s
            .route_kernel
            .observer
            .0
            .read()
            .map_err(|_| unavailable())?;
        if state.replay_publication() != Some(publication) {
            return Err(unavailable());
        }
        let active = state.active.as_ref().ok_or_else(unavailable)?;
        if origin.client.is_none()
            && (origin.ingress.is_some() || archived_resolver(&s, active).is_none())
        {
            return Err(unavailable());
        }
        Ok(state
            .select(name, origin)?
            .filter(|target| active.policy.history_match(target.zone, name).is_some()))
    }

    fn install(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
    ) -> io::Result<(bool, u64)> {
        self.install_answer(target, name, origin, answer, true, None)
    }

    fn install_replayed(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
        resolver: Option<&ArchiveResolver>,
    ) -> io::Result<(bool, u64)> {
        self.install_answer(target, name, origin, answer, false, resolver)
    }

    fn archive_history_matches(
        &self,
        publication: RoutePublication,
        name: &str,
        qtype: u16,
    ) -> io::Result<bool> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let state = s
            .route_kernel
            .observer
            .0
            .read()
            .map_err(|_| unavailable())?;
        state.archive_matches(publication, name, qtype)
    }

    fn install_history(
        &self,
        publication: RoutePublication,
        resolver: &ArchiveResolver,
        name: &str,
        answer: &RouteAnswer,
    ) -> io::Result<()> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let service = &s.route_kernel;
        let _guard = service.operations.try_lock().map_err(|_| unavailable())?;
        {
            let state = service.observer.0.read().map_err(|_| unavailable())?;
            if !state.archive_matches(publication, name, answer.qtype)?
                || state
                    .active
                    .as_ref()
                    .and_then(|active| archived_resolver(&s, active))
                    .is_none_or(|current| !resolver.same(&current))
            {
                return Err(unavailable());
            }
        }
        let request = ArchiveAnswer {
            revision: publication.revision,
            name,
            addresses: &answer.addresses,
            ttl: answer.ttl,
            qtype: answer.qtype,
        };
        let result = kernel::learn_archived_answer(
            &s.store,
            &System,
            request,
            |cfg, iface| super::routing_live_peer(&s, cfg, iface),
            || Self::invalidate_confirmation(&s),
        );
        if result.is_err() {
            Self::invalidate_confirmation(&s)?;
        }
        s.awg_runtime.invalidate_routing();
        result
    }
}

impl Hook {
    fn invalidate_confirmation(s: &AppState) -> io::Result<()> {
        s.route_kernel
            .observer
            .0
            .write()
            .map_err(|_| unavailable())?
            .invalidate();
        s.dnsserver.invalidate_routing_confirmations();
        Ok(())
    }

    fn install_answer(
        &self,
        target: RouteMatch,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: &RouteAnswer,
        observed: bool,
        resolver: Option<&ArchiveResolver>,
    ) -> io::Result<(bool, u64)> {
        let s = self.0.upgrade().ok_or_else(unavailable)?;
        let service = &s.route_kernel;
        let _guard = service.operations.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, RouteWriterBusy),
            TryLockError::Poisoned(_) => unavailable(),
        })?;
        let revision = {
            let state = service.observer.0.read().map_err(|_| unavailable())?;
            let active = state.active.as_ref().ok_or_else(unavailable)?;
            if !observed
                && (origin.client.is_none() && (origin.ingress.is_some() || resolver.is_none())
                    || resolver.is_some_and(|expected| {
                        archived_resolver(&s, active).is_none_or(|current| !expected.same(&current))
                    }))
            {
                return Err(unavailable());
            }
            if state.select(name, origin)? != Some(target) {
                return Err(unavailable());
            }
            if let Some(suppress) = state.cached(&s, target.zone, name, origin, answer, observed) {
                return Ok((suppress, state.epoch));
            }
            active.revision
        };
        let request = Answer {
            revision,
            zone: target.zone,
            addresses: &answer.addresses,
            ttl: answer.ttl,
            qtype: answer.qtype,
        };
        let result = kernel::learn_named_client_answer(
            &s.store,
            &System,
            request,
            origin,
            name,
            |cfg, iface| super::routing_live_peer(&s, cfg, iface),
            || Self::invalidate_confirmation(&s),
        );
        let mut state = service.observer.0.write().map_err(|_| unavailable())?;
        if result.is_err() {
            state.invalidate();
            s.dnsserver.invalidate_routing_confirmations();
        }
        let applied = result?;
        let suppress = applied.suppress;
        if observed {
            state.confirm(&s, target.zone, name, origin.client, &applied.accepted);
        }
        let now = Instant::now();
        state.hits.retain(|h| h.until > now);
        if state.hits.len() >= 32 {
            state.hits.pop_front();
        }
        state.hits.push_back(Hit {
            zone: target.zone,
            name: name.to_owned(),
            client: origin.client,
            ingress: origin.ingress.map(str::to_owned),
            qtype: answer.qtype,
            ips: answer.addresses.clone(),
            accepted: applied.accepted,
            until: now + Duration::from_secs(3),
            ttl: answer.ttl,
            suppress,
        });
        s.awg_runtime.invalidate_routing();
        Ok((suppress, state.epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_revalidation_hint_requires_the_current_global_or_exact_client_selection() {
        let routing: nfqws2_awg_rules::Routing = serde_json::from_value(serde_json::json!({
            "mode":"zones", "domain_source":"dnsproxy", "zones":[
                {"enabled":true,"route":"tunnel","domains":["*.device.test"],"source_ips":["192.168.1.25/32"]},
                {"enabled":true,"route":"tunnel","domains":["*.global.test"]},
                {"enabled":true,"route":"tunnel","domains":["*.lan.test"],"source_ips":["192.168.1.0/24"]}
            ]
        })).unwrap();
        let gate = Gate::default();
        gate.begin(kernel::Operation::Apply).unwrap();
        gate.publish(
            Ok(Some(Observation {
                policy: nfqws2_awg_rules::observed::Policy::compile(&routing).unwrap(),
                ready: true,
                revision: 4,
                trial_expires: 0,
                go_ipv4: false,
                block_aaaa: vec![],
            })),
            false,
        )
        .unwrap();
        let state = gate.0.read().unwrap();
        let origin = DnsOrigin {
            client: Some("192.168.1.25".parse().unwrap()),
            ingress: Some("br0"),
        };
        let scoped = state.select("sub.device.test", origin).unwrap().unwrap();
        let global = state.select("sub.global.test", origin).unwrap().unwrap();
        assert_eq!(
            state.firmware_hint_publication(scoped, "sub.device.test", origin),
            state.replay_publication()
        );
        let wrong_device = DnsOrigin {
            client: Some("192.168.1.26".parse().unwrap()),
            ..origin
        };
        assert!(state
            .firmware_hint_publication(scoped, "sub.device.test", wrong_device)
            .is_none());
        let range = state.select("sub.lan.test", origin).unwrap().unwrap();
        assert!(state
            .firmware_hint_publication(range, "sub.lan.test", origin)
            .is_none());
        assert_eq!(
            state.firmware_hint_publication(global, "sub.global.test", origin),
            state.replay_publication()
        );
        let obsolete = RouteMatch {
            generation: global.generation.wrapping_add(1),
            ..global
        };
        assert!(state
            .firmware_hint_publication(obsolete, "sub.global.test", origin)
            .is_none());
        let unattached = DnsOrigin {
            ingress: None,
            ..origin
        };
        assert!(state
            .firmware_hint_publication(global, "sub.global.test", unattached)
            .is_none());
        drop(state);
        let before = gate.confirmed_firmware_publication().unwrap();
        gate.begin(kernel::Operation::Refresh).unwrap();
        assert!(gate.confirmed_firmware_publication().is_none());
        let active = nfqws2_awg_rules::kernel::Observation {
            policy: nfqws2_awg_rules::observed::Policy::compile(&routing).unwrap(),
            ready: true,
            revision: before.revision,
            trial_expires: 0,
            go_ipv4: false,
            block_aaaa: vec![],
        };
        gate.publish(Ok(Some(active)), true).unwrap();
        assert!(gate.replay_publication().is_some());
        assert!(gate.confirmed_firmware_publication().is_none());
    }

    #[test]
    fn dns_fallback_epoch_tracks_completed_failure_not_an_update_or_absent_policy() {
        let gate = Gate::default();
        assert_eq!(gate.failure_epoch(), None);
        gate.begin(kernel::Operation::Apply).unwrap();
        assert_eq!(gate.failure_epoch(), None);
        gate.publish(Ok(None), true).unwrap();
        let first = gate.failure_epoch().unwrap();

        gate.begin(kernel::Operation::Refresh).unwrap();
        assert_eq!(gate.failure_epoch(), Some(first));
        gate.publish(Ok(None), false).unwrap();
        assert_eq!(gate.failure_epoch(), None);

        gate.begin(kernel::Operation::Recover).unwrap();
        assert!(gate.publish(Err(unavailable()), false).is_err());
        assert_ne!(gate.failure_epoch().unwrap(), first);
    }

    #[test]
    fn static_dns_attempt_requires_its_completed_failure_and_next_apply_epoch() {
        let gate = Gate::default();
        let initial = gate.idle_static_epoch(false).unwrap();
        assert!(gate.idle_static_epoch(true).is_none());
        gate.begin(kernel::Operation::Apply).unwrap();
        assert!(gate.started_static_apply(initial));
        assert!(gate.idle_static_epoch(true).is_none());
        gate.publish(Ok(None), true).unwrap();

        let failed = gate.idle_static_epoch(true).unwrap();
        assert!(initial != failed);
        gate.begin(kernel::Operation::Apply).unwrap();
        assert!(gate.started_static_apply(failed));
        assert!(!gate.started_static_apply(initial));
        gate.publish(Ok(None), false).unwrap();
        assert!(gate.idle_static_epoch(true).is_none());
        assert!(!gate.started_static_apply(failed));

        let healthy = gate.idle_static_epoch(false).unwrap();
        gate.begin(kernel::Operation::Refresh).unwrap();
        assert!(!gate.started_static_apply(healthy));
        assert!(gate.idle_static_epoch(false).is_none());
    }

    #[test]
    fn failed_dns_reply_receipt_requires_a_completed_unready_named_policy() {
        let gate = Gate::default();
        let routing = serde_json::from_value(serde_json::json!({
            "mode":"zones", "domain_source":"dnsproxy", "zones":[
                {"enabled":true,"domains":["*.office.test"],"source_ips":["192.168.1.0/24"]},
                {"enabled":true,"domains":["*"]}
            ]
        }))
        .unwrap();
        let observation = |ready, trial_expires, legacy| Observation {
            policy: if legacy {
                nfqws2_awg_rules::observed::Policy::compile_legacy_full(&routing).unwrap()
            } else {
                nfqws2_awg_rules::observed::Policy::compile(&routing).unwrap()
            },
            revision: 7,
            ready,
            trial_expires,
            block_aaaa: Vec::new(),
            go_ipv4: false,
        };
        let name = "host.office.test";
        let origin = DnsOrigin {
            client: Some("192.168.1.9".parse().unwrap()),
            ingress: None,
        };
        let proof = |who, name| {
            gate.0
                .read()
                .unwrap()
                .select(name, who)
                .err()
                .and_then(|error| error.get_ref()?.downcast_ref::<FailedRoute>().copied())
        };
        gate.begin(kernel::Operation::Apply).unwrap();
        assert_eq!(proof(origin, name), None);
        gate.publish(Ok(Some(observation(false, 0, false))), false)
            .unwrap();
        assert_eq!(proof(origin, name), None);
        gate.begin(kernel::Operation::Apply).unwrap();
        gate.publish(Ok(Some(observation(false, 0, false))), true)
            .unwrap();
        let failed = proof(origin, name).unwrap();
        assert_eq!(Some(failed.epoch), gate.failure_epoch());
        assert!(gate.blocked_static_names(&[name.to_owned()]).is_none());
        assert_eq!(proof(origin, "catchall.test"), None);
        assert_eq!(
            proof(
                DnsOrigin {
                    client: None,
                    ..origin
                },
                name
            ),
            None
        );
        assert_eq!(
            proof(
                DnsOrigin {
                    client: Some("192.168.2.9".parse().unwrap()),
                    ..origin
                },
                name
            ),
            None
        );
        gate.begin(kernel::Operation::Refresh).unwrap();
        assert_eq!(proof(origin, name), None);
        gate.publish(Ok(Some(observation(true, 0, false))), true)
            .unwrap();
        assert!(gate.0.read().unwrap().select(name, origin).is_ok());
        let rollback = gate.replay_publication().unwrap();
        assert!(!gate.0.read().unwrap().recovered(rollback, failed));
        gate.begin(kernel::Operation::Recover).unwrap();
        gate.publish(Ok(Some(observation(true, 0, false))), false)
            .unwrap();
        let recovered = gate.replay_publication().unwrap();
        assert_eq!(rollback.revision, recovered.revision);
        assert!(gate.0.read().unwrap().recovered(recovered, failed));
        assert!(!gate.0.read().unwrap().recovered(rollback, failed));

        gate.begin(kernel::Operation::Apply).unwrap();
        gate.publish(Ok(Some(observation(false, 1, false))), true)
            .unwrap();
        assert_eq!(proof(origin, name), None);
        gate.begin(kernel::Operation::Apply).unwrap();
        gate.publish(Ok(Some(observation(false, 0, true))), true)
            .unwrap();
        assert_eq!(proof(origin, name), None);
        gate.begin(kernel::Operation::Apply).unwrap();
        assert!(gate.publish(Err(unavailable()), true).is_err());
        assert_eq!(proof(origin, name), None);
    }

    #[test]
    fn replay_reselects_wildcard_against_the_exact_publication() {
        let dir = tempfile::tempdir().unwrap();
        let app = AppState::open(
            nfqws2_config::Config {
                data_dir: dir.path().display().to_string(),
                ..Default::default()
            },
            dir.path(),
            true,
        )
        .unwrap();
        let gate = &app.route_kernel.observer;
        let hook = Hook(std::sync::Arc::downgrade(&app));
        let publish = |mask| {
            let cfg = serde_json::from_value(serde_json::json!({
                "mode":"zones", "domain_source":"dnsproxy",
                "zones":[{"enabled":true,"domains":[mask],"source_ips":["192.0.2.3/32"]}]
            }))
            .unwrap();
            gate.publish(
                Ok(Some(Observation {
                    policy: nfqws2_awg_rules::observed::Policy::compile(&cfg).unwrap(),
                    revision: 4,
                    ready: true,
                    trial_expires: 0,
                    block_aaaa: Vec::new(),
                    go_ipv4: false,
                })),
                false,
            )
            .unwrap();
            gate.replay_publication().unwrap()
        };
        let name = "host.office.test";
        let origin = DnsOrigin {
            client: Some("192.0.2.3".parse().unwrap()),
            ingress: Some("br0"),
        };
        let before = publish("*.other.test");
        assert_eq!(hook.replay_target(before, name, origin).unwrap(), None);

        let after = publish("*.office.test");
        assert_eq!(before.revision, after.revision);
        assert_ne!(before.generation, after.generation);
        assert!(hook.replay_target(before, name, origin).is_err());
        let target = hook.replay_target(after, name, origin).unwrap().unwrap();
        assert_eq!(target.generation, after.generation);
        let foreign = DnsOrigin {
            client: Some("192.0.2.4".parse().unwrap()),
            ..origin
        };
        assert_eq!(hook.replay_target(after, name, foreign).unwrap(), None);
    }

    #[test]
    fn cached_addresses_require_same_name_and_ingress_even_under_one_winning_zone() {
        let dir = tempfile::tempdir().unwrap();
        let app = AppState::open(
            nfqws2_config::Config {
                data_dir: dir.path().display().to_string(),
                ..Default::default()
            },
            dir.path(),
            true,
        )
        .unwrap();
        let client = Some("192.0.2.3".parse().unwrap());
        let origin = DnsOrigin {
            client,
            ingress: Some("br0"),
        };
        let addresses = vec!["198.51.100.20".parse().unwrap()];
        let mut state = State::default();
        state.hits.push_back(Hit {
            zone: 2,
            name: "first.office.test".into(),
            client,
            ingress: Some("br0".into()),
            qtype: 1,
            ips: addresses.clone(),
            accepted: addresses.clone(),
            until: Instant::now() + Duration::from_secs(5),
            ttl: 30,
            suppress: false,
        });
        let answer = RouteAnswer {
            qtype: 1,
            addresses,
            ttl: 30,
        };
        assert_eq!(
            state.cached(&app, 2, "first.office.test", origin, &answer, true),
            Some(false)
        );
        assert_eq!(
            state.cached(&app, 2, "second.office.test", origin, &answer, true),
            None
        );
        assert_eq!(
            state.cached(
                &app,
                2,
                "first.office.test",
                DnsOrigin {
                    ingress: Some("br1"),
                    ..origin
                },
                &answer,
                true,
            ),
            None
        );
    }

    #[test]
    fn unrelated_dns_keeps_working_during_a_periodic_route_refresh() {
        let cfg = serde_json::from_value(serde_json::json!({
            "mode":"zones", "domain_source":"dnsproxy",
            "zones":[{"enabled":true,"domains":["*.office.test"]}]
        }))
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let app = AppState::open(
            nfqws2_config::Config {
                data_dir: dir.path().display().to_string(),
                ..Default::default()
            },
            dir.path(),
            true,
        )
        .unwrap();
        let gate = &app.route_kernel.observer;
        let observation = || Observation {
            policy: nfqws2_awg_rules::observed::Policy::compile(&cfg).unwrap(),
            revision: 4,
            ready: true,
            trial_expires: 0,
            block_aaaa: vec![0],
            go_ipv4: false,
        };
        gate.publish(Ok(Some(observation())), false).unwrap();
        gate.begin(kernel::Operation::Refresh).unwrap();
        let origin = DnsOrigin {
            client: None,
            ingress: None,
        };
        {
            let state = gate.0.read().unwrap();
            assert_eq!(state.select("ordinary.test", origin).unwrap(), None);
            assert!(state.select("a.office.test", origin).is_err());
        }
        let hook = Hook(std::sync::Arc::downgrade(&app));
        let (epoch, initial) = hook.capture_redirect("a.office.test", origin);
        let epoch = epoch.unwrap();
        assert!(initial.is_err());
        assert_eq!(epoch.zone, Some(0));
        assert!(epoch.suppress_aaaa);
        assert!(matches!(
            hook.select_redirect_for_delivery("a.office.test", origin, epoch),
            Ok(DeliverySelection::Pending(_))
        ));
        let (outside, initial) = hook.capture_redirect("ordinary.test", origin);
        assert_eq!(initial.unwrap(), None);
        assert!(!outside.unwrap().suppress_aaaa);
        let query = nfqws2_dns::build_query("ordinary.test", 1, 1).unwrap();
        let mut reply = nfqws2_dns::response_error(&query, 0);
        reply[7] = 1;
        reply.extend_from_slice(&[192, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 7]);
        hook.record_reply("ordinary.test", origin, None, &reply, false);
        let counters = serde_json::to_value(app.trace.awg.counters()).unwrap();
        assert_eq!(counters["dns"], 1);
        assert_eq!(counters["direct"], 1);
        assert!(gate.publish(Err(unavailable()), false).is_err());
        assert!(hook
            .select_redirect_for_delivery("a.office.test", origin, epoch)
            .is_err());
        assert!(gate
            .0
            .read()
            .unwrap()
            .select("ordinary.test", origin)
            .is_err());
        let captured_during_failure = |gate: &Gate| {
            let (epoch, initial) = hook.capture_redirect("a.office.test", origin);
            let epoch = epoch.unwrap();
            assert!(initial.is_err());
            assert!(epoch.suppress_aaaa);
            assert!(epoch.unavailable);
            assert!(hook
                .select_redirect_for_delivery("a.office.test", origin, epoch)
                .is_err());
            assert_eq!(gate.waiting_dns_queries(), 0);
            epoch
        };
        let failed = captured_during_failure(gate);
        gate.begin(kernel::Operation::Apply).unwrap();
        let replacing = captured_during_failure(gate);
        gate.publish(Ok(Some(observation())), false).unwrap();
        for capture in [failed, replacing] {
            assert!(hook
                .select_redirect_for_delivery("a.office.test", origin, capture)
                .is_err());
        }
        let (fresh, initial) = hook.capture_redirect("a.office.test", origin);
        assert!(initial.unwrap().is_some());
        assert!(matches!(
            hook.select_redirect_for_delivery("a.office.test", origin, fresh.unwrap()),
            Ok(DeliverySelection::Ready(Some(_)))
        ));
    }
}
