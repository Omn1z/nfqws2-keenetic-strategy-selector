use super::{kernel, observer::StaticApplyEpoch, DnsRequest, DnsSnapshot, Shared, System};
use crate::dnsserver::{ArchiveResolver, ManagedOriginReceipt};
use futures_util::{stream, StreamExt};
use std::{
    cell::Cell,
    collections::BTreeMap,
    io,
    net::IpAddr,
    sync::{atomic::Ordering, Mutex},
    time::{Duration, Instant},
};

const HINT_LIMIT: Duration = Duration::from_secs(20 * 60);

#[derive(Clone, Eq, PartialEq)]
pub(super) enum Baseline {
    Confirmed(kernel::ConfirmedStaticDnsRetry),
    Cold(kernel::ColdStaticDnsDraft),
}

impl Baseline {
    fn request(&self) -> &DnsRequest {
        match self {
            Self::Confirmed(ticket) => &ticket.snapshot().request,
            Self::Cold(draft) => draft.request(),
        }
    }

    fn snapshot(&self) -> Option<&DnsSnapshot> {
        match self {
            Self::Confirmed(ticket) => Some(ticket.snapshot()),
            Self::Cold(_) => None,
        }
    }

    fn matches(&self, receipt: &kernel::FailedStaticDnsApply) -> bool {
        match self {
            Self::Confirmed(ticket) => receipt.baseline() == Some(ticket),
            Self::Cold(draft) => receipt.cold_draft() == Some(draft),
        }
    }
}

#[derive(Clone)]
enum Proposal<R> {
    Confirmed,
    Changed {
        snapshot: DnsSnapshot,
        compensated: Option<R>,
    },
}

impl<R> Proposal<R> {
    fn snapshot<'a>(&'a self, confirmed: Option<&'a DnsSnapshot>) -> Option<&'a DnsSnapshot> {
        match self {
            Self::Confirmed => confirmed,
            Self::Changed { snapshot, .. } => Some(snapshot),
        }
    }
}

#[derive(Clone)]
struct Candidate<T, R> {
    ticket: T,
    proposal: Proposal<R>,
    resolver: ManagedOriginReceipt,
    expires: Instant,
}

impl<T, R> Candidate<T, R> {
    fn check_resolver(&self, s: &Shared) -> io::Result<()> {
        if Instant::now() >= self.expires {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if !resolver_current(s, &self.resolver) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

fn resolver_current(s: &Shared, resolver: &ManagedOriginReceipt) -> bool {
    s.dnsserver
        .archive_resolver()
        .is_some_and(|current| resolver.same(&current))
}

struct ManagedSource {
    epoch: StaticApplyEpoch,
    resolver: ArchiveResolver,
    origin: ManagedOriginReceipt,
}

fn managed_source(s: &Shared) -> Option<ManagedSource> {
    let epoch = s.route_kernel.observer.idle_static_epoch(false)?;
    let (_, resolver) = s.dnsserver.routing_recovery_resolver().ok()??;
    let origin = resolver.managed_origin_receipt()?;
    Some(ManagedSource {
        epoch,
        resolver,
        origin,
    })
}

#[derive(Clone)]
pub(super) struct Hint<T = Baseline, R = kernel::FailedStaticDnsApply> {
    candidate: Candidate<T, R>,
    failed: StaticApplyEpoch,
    command_generation: usize,
}

pub(super) struct Proof<T = Baseline, R = kernel::FailedStaticDnsApply> {
    candidate: Candidate<T, R>,
    epoch: StaticApplyEpoch,
    command_generation: usize,
    retry: bool,
    writer_verified: Cell<bool>,
}

pub(super) enum Prepared<T = Baseline, R = kernel::FailedStaticDnsApply> {
    Checked(Proof<T, R>),
    Fresh {
        snapshot: DnsSnapshot,
        expires: Instant,
        origin: ManagedOriginReceipt,
    },
}

enum Batch {
    Fresh {
        answers: BTreeMap<String, Vec<IpAddr>>,
        expires: Instant,
        all_families_positive: bool,
    },
    MatchingTimeout(io::Error),
    Rejected(io::Error),
}

#[derive(Clone)]
struct Query {
    name: String,
    kind: u16,
}

impl Query {
    fn ipv4(&self) -> bool {
        self.kind == 1
    }
}

enum Answer {
    Positive(Vec<IpAddr>, Instant),
    NoData,
    UpstreamTimeout(io::Error),
    Failed(io::Error),
}

impl From<io::Result<(Vec<IpAddr>, Instant)>> for Answer {
    fn from(result: io::Result<(Vec<IpAddr>, Instant)>) -> Self {
        match result {
            Ok((ips, expires)) => Self::Positive(ips, expires),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self::NoData,
            Err(error) if crate::dnsserver::is_managed_upstream_timeout(&error) => {
                Self::UpstreamTimeout(error)
            }
            Err(error) => Self::Failed(error),
        }
    }
}

fn queries(request: &DnsRequest) -> impl Iterator<Item = Query> + '_ {
    request.names.iter().flat_map(|name| {
        let v6_only = request.ipv6_only.binary_search(name).is_ok();
        let dual = request.dual_stack.binary_search(name).is_ok();
        [(!v6_only, 1), (v6_only || dual, 28)]
            .into_iter()
            .filter(move |(wanted, _)| *wanted)
            .map(move |(_, kind)| Query {
                name: name.clone(),
                kind,
            })
    })
}

fn summarize(
    request: &DnsRequest,
    expected: Option<&DnsSnapshot>,
    replies: impl IntoIterator<Item = (Query, Answer)>,
    now: Instant,
    deadline: Instant,
) -> Batch {
    let mut answers: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    let mut expires: Option<Instant> = None;
    let mut timeout = None;
    let mut conflict = false;
    let mut all_families_positive = true;
    let mut completed = 0;
    // The caller collects every result, including the last authoritative
    // negative or changed family after another lookup already timed out.
    for (query, answer) in replies {
        completed += 1;
        match answer {
            Answer::Positive(ips, until) => {
                conflict |= expected.is_some_and(|snapshot| {
                    !snapshot.answers.get(&query.name).is_some_and(|saved| {
                        saved
                            .iter()
                            .filter(|ip| ip.is_ipv4() == query.ipv4())
                            .eq(ips.iter())
                    })
                });
                answers.entry(query.name).or_default().extend(ips);
                expires = Some(expires.map_or(until, |earlier| earlier.min(until)));
            }
            Answer::NoData => {
                conflict = true;
                all_families_positive = false;
            }
            Answer::UpstreamTimeout(error) => timeout = Some(error),
            Answer::Failed(error) => return Batch::Rejected(error),
        }
    }
    if completed != request.names.len() + request.dual_stack.len()
        || now >= deadline
        || expires.is_some_and(|until| now >= until)
    {
        return Batch::Rejected(io::ErrorKind::TimedOut.into());
    }
    if let Some(error) = timeout {
        return if expected.is_none() || conflict {
            Batch::Rejected(error)
        } else {
            Batch::MatchingTimeout(error)
        };
    }
    let Some(expires) = expires.filter(|_| answers.len() == request.names.len()) else {
        return Batch::Rejected(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS не вернул подходящих адресов",
        ));
    };
    for addresses in answers.values_mut() {
        addresses.sort_unstable();
        addresses.dedup();
    }
    Batch::Fresh {
        answers,
        expires,
        all_families_positive,
    }
}

async fn resolve_batch(
    resolver: &ArchiveResolver,
    request: &DnsRequest,
    expected: Option<&DnsSnapshot>,
    deadline: Instant,
    current: impl Fn() -> bool,
) -> Batch {
    let current = &current;
    let replies = stream::iter(queries(request).map(|query| async move {
        let result = super::super::resolve::managed_family(
            resolver,
            &query.name,
            deadline,
            query.kind,
            current,
        )
        .await;
        (query, result.into())
    }))
    .buffer_unordered(2)
    .collect::<Vec<_>>()
    .await;
    summarize(request, expected, replies, Instant::now(), deadline)
}

impl Proof {
    pub(super) fn confirmed_ticket(&self) -> &kernel::ConfirmedStaticDnsRetry {
        match &self.candidate.ticket {
            Baseline::Confirmed(ticket) => ticket,
            Baseline::Cold(_) => unreachable!("first static Apply has no confirmed addresses"),
        }
    }

    pub(super) fn snapshot(&self) -> &DnsSnapshot {
        self.candidate
            .proposal
            .snapshot(self.candidate.ticket.snapshot())
            .expect("checked static Apply snapshot")
    }

    pub(super) fn proposed_apply(&self) -> Option<kernel::ManagedStaticDnsApply<'_>> {
        let (snapshot, compensated) = match &self.candidate.proposal {
            Proposal::Confirmed => return None,
            Proposal::Changed {
                snapshot,
                compensated,
            } => (snapshot, compensated),
        };
        Some(match compensated.as_ref() {
            Some(receipt) => kernel::ManagedStaticDnsApply::Retry(receipt),
            None => match &self.candidate.ticket {
                Baseline::Confirmed(ticket) => {
                    kernel::ManagedStaticDnsApply::Fresh(ticket, snapshot)
                }
                Baseline::Cold(draft) => kernel::ManagedStaticDnsApply::Cold(draft, snapshot),
            },
        })
    }

    pub(super) fn is_fresh_proposal(&self) -> bool {
        matches!(
            self.candidate.proposal,
            Proposal::Changed {
                compensated: None,
                ..
            }
        )
    }
}

impl<T, R> Proof<T, R> {
    pub(super) fn check_apply(&self, s: &Shared) -> io::Result<()> {
        if s.route_kernel.observer.idle_static_epoch(self.retry) != Some(self.epoch) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.check_current(s)
    }

    pub(super) fn verify_writer(&self, s: &Shared) -> io::Result<()> {
        if !s.route_kernel.observer.started_static_apply(self.epoch) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.check_current(s)?;
        self.writer_verified.set(true);
        Ok(())
    }

    fn check_current(&self, s: &Shared) -> io::Result<()> {
        if self.command_generation != s.route_kernel.generation.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.candidate.check_resolver(s)
    }
}

pub(super) fn prepare(
    s: &Shared,
    request: &DnsRequest,
    deadline: Instant,
    managed_blocked: bool,
) -> io::Result<Option<Prepared>> {
    let Some(source) = managed_source(s) else {
        return Ok(None);
    };
    let Some(baseline) = kernel::confirmed_static_dns_retry(&s.store, request)
        .ok()
        .flatten()
        .map(Baseline::Confirmed)
        .or_else(|| {
            // Leave lookup time after the optional empty-kernel probe.
            let now = Instant::now();
            let probe_deadline = now + deadline.saturating_duration_since(now) / 2;
            kernel::cold_static_dns_draft_until(&s.store, &System, request, probe_deadline)
                .ok()
                .flatten()
                .map(Baseline::Cold)
        })
    else {
        return Ok(None);
    };
    prepare_with(
        s,
        &s.route_kernel.static_dns,
        &baseline,
        (baseline.request(), baseline.snapshot()),
        source,
        deadline,
        managed_blocked,
    )
}

fn prepare_with<T: Clone + Eq, R: Clone>(
    s: &Shared,
    slot: &Mutex<Option<Hint<T, R>>>,
    ticket: &T,
    (request, confirmed): (&DnsRequest, Option<&DnsSnapshot>),
    ManagedSource {
        epoch,
        resolver,
        origin,
    }: ManagedSource,
    deadline: Instant,
    managed_blocked: bool,
) -> io::Result<Option<Prepared<T, R>>> {
    let command_generation = s.route_kernel.generation.load(Ordering::Acquire);
    let saved_hint = slot
        .lock()
        .map_err(|error| io::Error::other(error.to_string()))?
        .clone();
    let hint = saved_hint.filter(|hint| {
        hint.command_generation == command_generation
            && hint.failed == epoch
            && s.route_kernel.observer.idle_static_epoch(true) == Some(epoch)
            && &hint.candidate.ticket == ticket
            && hint.candidate.resolver.same(&resolver)
            && hint.candidate.check_resolver(s).is_ok()
    });
    let current = move |s: &Shared, origin: &ManagedOriginReceipt| {
        s.route_kernel.observer.idle_static_epoch(false) == Some(epoch)
            && s.route_kernel.generation.load(Ordering::Acquire) == command_generation
            && resolver_current(s, origin)
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return Ok(None);
    };
    let expected = hint
        .as_ref()
        .and_then(|hint| hint.candidate.proposal.snapshot(confirmed))
        .or(confirmed)
        .cloned();
    let (state, pinned, source, requested) = (s.clone(), resolver, origin.clone(), request.clone());
    let job = runtime.spawn(async move {
        Box::pin(resolve_batch(
            &pinned,
            &requested,
            expected.as_ref(),
            deadline,
            || current(&state, &source),
        ))
        .await
    });
    let answer = match runtime.block_on(job) {
        Ok(answer) => answer,
        Err(error) if managed_blocked || hint.is_some() => return Err(io::Error::other(error)),
        Err(_) => return Ok(None),
    };
    if !current(s, &origin) {
        return if managed_blocked || hint.is_some() {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Ok(None)
        };
    }
    let (candidate, retry) = match answer {
        Batch::Fresh {
            answers,
            expires,
            all_families_positive,
        } => {
            let proposal = if confirmed.is_some_and(|snapshot| snapshot.answers == answers) {
                Proposal::Confirmed
            } else {
                discard(slot, epoch);
                let snapshot = DnsSnapshot {
                    request: request.clone(),
                    answers,
                };
                if !all_families_positive {
                    return Ok(Some(Prepared::Fresh {
                        snapshot,
                        expires,
                        origin,
                    }));
                }
                Proposal::Changed {
                    snapshot,
                    compensated: None,
                }
            };
            (
                Candidate {
                    ticket: ticket.clone(),
                    proposal,
                    resolver: origin,
                    expires: expires.min(Instant::now() + HINT_LIMIT),
                },
                false,
            )
        }
        Batch::MatchingTimeout(error) | Batch::Rejected(error) if hint.is_none() => {
            return if managed_blocked {
                Err(error)
            } else {
                Ok(None)
            };
        }
        Batch::MatchingTimeout(error) => {
            let hint = hint.ok_or(error)?;
            hint.candidate.check_resolver(s)?;
            (hint.candidate, true)
        }
        Batch::Rejected(error) => {
            discard(slot, epoch);
            return Err(error);
        }
    };
    let proof = Proof {
        candidate,
        epoch,
        command_generation,
        retry,
        writer_verified: Cell::new(false),
    };
    proof.check_apply(s)?;
    Ok(Some(Prepared::Checked(proof)))
}

fn discard<T, R>(slot: &Mutex<Option<Hint<T, R>>>, epoch: StaticApplyEpoch) {
    if let Ok(mut slot) = slot.lock() {
        if slot.as_ref().is_some_and(|hint| hint.failed == epoch) {
            *slot = None;
        }
    }
}

/// Retain only the verified administrative input of this completed static Apply.
pub(super) fn finish(
    s: &Shared,
    proof: Option<&Proof>,
    command_generation: usize,
    result: &io::Result<()>,
) {
    let compensated = proof
        .zip(
            result
                .as_ref()
                .err()
                .and_then(kernel::failed_static_dns_apply),
        )
        .filter(|(proof, receipt)| {
            proof.candidate.ticket.matches(receipt) && receipt.snapshot() == proof.snapshot()
        })
        .map(|(_, receipt)| receipt.clone());
    finish_into(
        s,
        &s.route_kernel.static_dns,
        proof,
        command_generation,
        result.is_err(),
        compensated,
    );
}

fn finish_into<T: Clone, R: Clone>(
    s: &Shared,
    slot: &Mutex<Option<Hint<T, R>>>,
    proof: Option<&Proof<T, R>>,
    command_generation: usize,
    failed: bool,
    compensated: Option<R>,
) {
    let next = proof
        .zip(s.route_kernel.observer.idle_static_epoch(true))
        .filter(|(proof, _)| {
            failed && proof.writer_verified.get() && proof.candidate.check_resolver(s).is_ok()
        })
        .and_then(|(proof, failed)| {
            let mut candidate = proof.candidate.clone();
            if let Proposal::Changed {
                compensated: receipt,
                ..
            } = &mut candidate.proposal
            {
                // A verified preflight does not prove either a writer failure
                // or restoration of the prior installed generation.
                *receipt = Some(compensated?);
            }
            Some(Hint {
                candidate,
                failed,
                command_generation,
            })
        });
    if let Ok(mut slot) = slot.lock() {
        *slot = next;
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct StaticApplyFixture(Mutex<Option<Hint<DnsSnapshot, ()>>>);

#[cfg(test)]
#[derive(Default)]
pub(crate) struct StaticInitialApplyFixture(Mutex<Option<Hint<(String, DnsRequest), ()>>>);

#[cfg(test)]
pub(crate) enum StaticApplyFixtureFailure {
    Unverified(io::Error),
    Compensated(io::Error),
}

#[cfg(test)]
pub(crate) fn static_apply_for_test(
    s: &Shared,
    fixture: &StaticApplyFixture,
    confirmed: &DnsSnapshot,
    apply: impl FnOnce(&DnsSnapshot, bool, Instant) -> io::Result<()>,
) -> io::Result<()> {
    static_apply_fixture(
        s,
        &fixture.0,
        confirmed,
        (&confirmed.request, Some(confirmed), false),
        |snapshot, reused, expires| {
            apply(snapshot, reused, expires).map_err(StaticApplyFixtureFailure::Unverified)
        },
    )
}

#[cfg(test)]
pub(crate) fn static_proposal_apply_for_test(
    s: &Shared,
    fixture: &StaticApplyFixture,
    confirmed: &DnsSnapshot,
    apply: impl FnOnce(&DnsSnapshot, bool, Instant) -> Result<(), StaticApplyFixtureFailure>,
) -> io::Result<()> {
    static_apply_fixture(
        s,
        &fixture.0,
        confirmed,
        (&confirmed.request, Some(confirmed), true),
        apply,
    )
}

#[cfg(test)]
pub(crate) fn static_initial_apply_for_test(
    s: &Shared,
    fixture: &StaticInitialApplyFixture,
    request: &DnsRequest,
    boot: &str,
    apply: impl FnOnce(&DnsSnapshot, bool, Instant) -> Result<(), StaticApplyFixtureFailure>,
) -> io::Result<()> {
    let ticket = (boot.to_owned(), request.clone());
    static_apply_fixture(s, &fixture.0, &ticket, (request, None, true), apply)
}

#[cfg(test)]
fn static_apply_fixture<T: Clone + Eq>(
    s: &Shared,
    slot: &Mutex<Option<Hint<T, ()>>>,
    ticket: &T,
    (request, confirmed, allow_proposal): (&DnsRequest, Option<&DnsSnapshot>, bool),
    apply: impl FnOnce(&DnsSnapshot, bool, Instant) -> Result<(), StaticApplyFixtureFailure>,
) -> io::Result<()> {
    if kernel::dns_request(&s.store, super::Operation::Apply)?.as_ref() != Some(request) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let deadline = Instant::now() + super::DNS_BUDGET;
    let source = managed_source(s).ok_or(io::ErrorKind::NotFound)?;
    let Some(Prepared::Checked(proof)) = prepare_with(
        s,
        slot,
        ticket,
        (request, confirmed),
        source,
        deadline,
        false,
    )?
    else {
        return Err(io::ErrorKind::NotFound.into());
    };
    if !allow_proposal && !matches!(proof.candidate.proposal, Proposal::Confirmed) {
        return Err(io::ErrorKind::NotFound.into());
    }
    let _guard = s
        .route_kernel
        .operations
        .lock()
        .map_err(|error| io::Error::other(error.to_string()))?;
    proof.check_apply(s)?;
    let mut compensated = None;
    let result = super::publish_after_classified(s, super::Operation::Apply, || {
        let result = (|| {
            proof.verify_writer(s)?;
            match apply(
                proof
                    .candidate
                    .proposal
                    .snapshot(confirmed)
                    .ok_or(io::ErrorKind::InvalidData)?,
                proof.retry,
                proof.candidate.expires,
            ) {
                Ok(()) => Ok(()),
                Err(StaticApplyFixtureFailure::Unverified(error)) => Err(error),
                Err(StaticApplyFixtureFailure::Compensated(error)) => {
                    compensated = Some(());
                    Err(error)
                }
            }
        })();
        let op = super::Operation::Apply;
        let outcome = if compensated.is_some()
            && matches!(proof.candidate.proposal, Proposal::Changed { .. })
        {
            super::observer::PublicationOutcome::CompensatedStatic
        } else {
            super::observer::PublicationOutcome::from_result(op, &result)
        };
        (result, outcome)
    });
    let generation = s
        .route_kernel
        .generation
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    finish_into(
        s,
        slot,
        Some(&proof),
        generation,
        result.is_err(),
        compensated,
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summarize(
        snapshot: &DnsSnapshot,
        replies: impl IntoIterator<Item = (Query, Answer)>,
        now: Instant,
        deadline: Instant,
    ) -> Batch {
        super::summarize(&snapshot.request, Some(snapshot), replies, now, deadline)
    }

    fn request() -> DnsSnapshot {
        let addresses = |a: &[&str]| a.iter().map(|raw| raw.parse().unwrap()).collect();
        DnsSnapshot {
            request: DnsRequest {
                revision: 7,
                names: ["alpha.test", "beta.test", "gamma.test"]
                    .map(str::to_owned)
                    .into(),
                dual_stack: vec!["alpha.test".into()],
                ipv6_only: vec!["gamma.test".into()],
            },
            answers: BTreeMap::from([
                (
                    "alpha.test".into(),
                    addresses(&["192.0.2.11", "2001:db8::11"]),
                ),
                ("beta.test".into(), addresses(&["192.0.2.12"])),
                ("gamma.test".into(), addresses(&["2001:db8::13"])),
            ]),
        }
    }

    #[test]
    fn batch_timeout_cannot_hide_another_family_result_or_unfinished_lookup() {
        let snapshot = request();
        let names: Vec<_> = queries(&snapshot.request).collect();
        let now = Instant::now();
        let end = now + Duration::from_secs(8);
        let positive = |ip: &str| Answer::Positive(vec![ip.parse().unwrap()], end);
        let replies = |alpha_v6| {
            [
                (
                    names[0].clone(),
                    Answer::UpstreamTimeout(io::ErrorKind::TimedOut.into()),
                ),
                (names[2].clone(), positive("192.0.2.12")),
                (names[3].clone(), positive("2001:db8::13")),
                (names[1].clone(), alpha_v6),
            ]
        };
        assert!(matches!(
            summarize(&snapshot, replies(positive("2001:db8::11")), now, end),
            Batch::MatchingTimeout(_)
        ));
        for late in [
            positive("2001:db8::21"),
            Answer::NoData,
            Answer::Failed(io::ErrorKind::InvalidData.into()),
            Answer::Failed(io::ErrorKind::TimedOut.into()),
        ] {
            assert!(matches!(
                summarize(&snapshot, replies(late), now, end),
                Batch::Rejected(_)
            ));
        }
        assert!(matches!(
            summarize(
                &snapshot,
                replies(positive("2001:db8::11")).into_iter().take(3),
                now,
                end,
            ),
            Batch::Rejected(_)
        ));
    }

    #[test]
    fn timeout_compares_other_families_to_the_compensated_proposal() {
        let confirmed = request();
        let mut rotated = confirmed.clone();
        rotated.answers.get_mut("alpha.test").unwrap()[1] = "2001:db8::21".parse().unwrap();
        let proposal = Proposal::Changed {
            snapshot: rotated,
            compensated: Some(()),
        };
        let now = Instant::now();
        let deadline = now + Duration::from_secs(8);
        let answers = |v6: &str| {
            queries(&confirmed.request)
                .map(move |query| {
                    let answer = match (query.name.as_str(), query.kind) {
                        ("alpha.test", 1) => {
                            Answer::UpstreamTimeout(io::ErrorKind::TimedOut.into())
                        }
                        ("alpha.test", 28) => Answer::Positive(vec![v6.parse().unwrap()], deadline),
                        ("beta.test", 1) => {
                            Answer::Positive(vec!["192.0.2.12".parse().unwrap()], deadline)
                        }
                        ("gamma.test", 28) => {
                            Answer::Positive(vec!["2001:db8::13".parse().unwrap()], deadline)
                        }
                        _ => unreachable!(),
                    };
                    (query, answer)
                })
                .collect::<Vec<_>>()
        };
        let expected = proposal.snapshot(Some(&confirmed)).unwrap();
        assert!(matches!(
            summarize(expected, answers("2001:db8::21"), now, deadline),
            Batch::MatchingTimeout(_)
        ));
        assert!(matches!(
            summarize(expected, answers("2001:db8::11"), now, deadline),
            Batch::Rejected(_)
        ));
    }

    #[test]
    fn fresh_batch_keeps_family_nodata_and_uses_the_minimum_positive_ttl() {
        let snapshot = request();
        let names: Vec<_> = queries(&snapshot.request).collect();
        assert_eq!(
            names
                .iter()
                .map(|query| (query.name.as_str(), query.kind))
                .collect::<Vec<_>>(),
            [
                ("alpha.test", 1),
                ("alpha.test", 28),
                ("beta.test", 1),
                ("gamma.test", 28),
            ]
        );
        let now = Instant::now();
        let short = now + Duration::from_secs(20);
        let long = now + Duration::from_secs(40);
        let positive = |ip: &str, until| Answer::Positive(vec![ip.parse().unwrap()], until);
        let replies = [
            (names[0].clone(), positive("192.0.2.11", long)),
            (names[1].clone(), Answer::NoData),
            (names[2].clone(), positive("192.0.2.12", short)),
            (names[3].clone(), positive("2001:db8::13", long)),
        ];
        let Batch::Fresh {
            answers,
            expires,
            all_families_positive,
        } = summarize(&snapshot, replies, now, long)
        else {
            panic!("an ordinary dual-stack snapshot can have NODATA for one family");
        };
        assert!(!all_families_positive);
        assert_eq!(expires, short);
        assert_eq!(
            answers["alpha.test"],
            ["192.0.2.11".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(answers["gamma.test"], snapshot.answers["gamma.test"]);
    }

    #[test]
    fn cold_batch_needs_a_complete_fresh_answer_before_any_compensated_snapshot() {
        let data = request();
        let request = &data.request;
        let now = Instant::now();
        let deadline = now + Duration::from_secs(8);
        let reply = |query: Query| {
            let ips = data.answers[&query.name]
                .iter()
                .filter(|ip| ip.is_ipv4() == query.ipv4())
                .copied()
                .collect();
            (query, Answer::Positive(ips, deadline))
        };
        let fresh = queries(request).map(reply);
        assert!(matches!(
            super::summarize(request, None, fresh, now, deadline),
            Batch::Fresh {
                all_families_positive: true,
                ..
            }
        ));
        let timeout = queries(request).enumerate().map(|(i, query)| {
            if i == 0 {
                (
                    query,
                    Answer::UpstreamTimeout(io::ErrorKind::TimedOut.into()),
                )
            } else {
                reply(query)
            }
        });
        assert!(matches!(
            super::summarize(request, None, timeout, now, deadline),
            Batch::Rejected(_)
        ));
    }
}
