use super::{kernel, observer, Shared};
use crate::dnsserver::{FailedRoute, ManagedOriginReceipt, WarmDnsObservation};
use std::{
    io,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct State {
    watching: Option<Watch>,
    serial: u64,
}

struct Watch {
    failure: FailedRoute,
    profile: kernel::WarmNamedReplacementRequest,
    hint: Option<Hint>,
}

#[derive(Clone)]
struct Hint {
    serial: u64,
    addresses: Vec<IpAddr>,
    expires: Instant,
    resolver: ManagedOriginReceipt,
    // Keep the actual observed upstream and method, without logging the raw
    // response or using answers from another resolver selection.
    upstream: String,
    route: String,
}

pub(crate) struct WarmConfirmation {
    failure: FailedRoute,
    profile: kernel::WarmNamedReplacementRequest,
    hint: Hint,
}

pub(crate) struct ProfileNames {
    pub(crate) names: kernel::NamedActiveReplacement,
    pub(crate) warm: Option<WarmConfirmation>,
}

impl WarmConfirmation {
    pub(crate) fn verify(&self, s: &Shared) -> io::Result<()> {
        if s.route_kernel.observer.named_transport_failure() != Some(self.failure) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.verify_origin(s)
    }

    pub(crate) fn verify_origin(&self, s: &Shared) -> io::Result<()> {
        if self.hint.expires <= Instant::now() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let state = s
            .route_kernel
            .warm_named
            .try_lock()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        if !state.watching.as_ref().is_some_and(|watch| {
            watch.failure == self.failure
                && watch.profile == self.profile
                && watch.hint.as_ref().is_some_and(|hint| {
                    hint.serial == self.hint.serial
                        && hint.upstream == self.hint.upstream
                        && hint.route == self.hint.route
                })
        }) || !s
            .dnsserver
            .routing_recovery_resolver()?
            .is_some_and(|(_, resolver)| self.hint.resolver.same(&resolver))
        {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

pub(super) fn replace_capture(s: &Shared, arm: bool) {
    // A real failed writer provides the epoch. A matching, stable native
    // profile pair limits the capture to one router-local transport name.
    let failure = arm
        .then(|| s.route_kernel.observer.named_transport_failure())
        .flatten();
    let watch = if failure.is_some() {
        failure.zip(
            kernel::warm_named_replacement_request(&s.store)
                .ok()
                .flatten(),
        )
    } else {
        None
    }
    .map(|(failure, profile)| Watch {
        failure,
        profile,
        hint: None,
    });
    if let Ok(mut state) = s.route_kernel.warm_named.lock() {
        state.watching = watch;
    }
}

pub(super) fn capture(s: &Shared, name: &str) -> Option<FailedRoute> {
    let failure = s.route_kernel.observer.named_transport_failure()?;
    let state = s.route_kernel.warm_named.try_lock().ok()?;
    let watch = state.watching.as_ref()?;
    (watch.failure == failure && watch.profile.host() == name).then_some(failure)
}

pub(super) fn observe(s: &Shared, value: WarmDnsObservation<'_>) {
    let WarmDnsObservation {
        failure,
        name,
        query,
        reply,
        anchor,
        resolver,
        source,
    } = value;
    if s.route_kernel.observer.named_transport_failure() != Some(failure)
        || source.route == "shadow"
        || source.route.is_empty()
        || source.upstream.is_empty()
        || !s
            .dnsserver
            .routing_recovery_resolver()
            .ok()
            .flatten()
            .is_some_and(|(_, current)| resolver.same(&current))
        || query.get(10..12) != Some(&[0, 0])
        || nfqws2_dns::validate_answer(query, reply).is_err()
    {
        return;
    }
    let Ok((domain, kind)) = nfqws2_dns::query_domain(query) else {
        return;
    };
    if domain != name {
        return;
    }
    let Ok(mut state) = s.route_kernel.warm_named.try_lock() else {
        return;
    };
    state.serial = state.serial.wrapping_add(1);
    let serial = state.serial;
    let Some(watch) = state
        .watching
        .as_mut()
        .filter(|watch| watch.failure == failure && watch.profile.host() == name)
    else {
        return;
    };
    let exact = nfqws2_dns::exact_address_step(reply, kind);
    if kind == 1 {
        if reply.get(3).is_some_and(|flags| flags & 15 == 3)
            || exact.is_ok_and(|(_, addresses)| !addresses.is_empty())
        {
            watch.hint = None;
        }
        return;
    }
    if kind != 28 {
        return;
    }
    // A new authoritative answer replaces the entire prior cohort. Mixed,
    // empty, malformed and expired records cannot supplement older addresses.
    watch.hint = None;
    let Ok((aliases, addresses)) = exact else {
        return;
    };
    let Ok(Some(answer)) = nfqws2_dns::route_answer(reply) else {
        return;
    };
    if !aliases.is_empty()
        || addresses.is_empty()
        || addresses.len() > 16
        || answer.addresses != addresses
        || addresses.iter().any(|ip| !ip.is_ipv6())
        || answer.ttl == 0
    {
        return;
    }
    let expires = anchor + Duration::from_secs(u64::from(answer.ttl).min(20 * 60));
    if expires <= Instant::now() {
        return;
    }
    watch.hint = Some(Hint {
        serial,
        addresses,
        expires,
        resolver,
        upstream: source.upstream.clone(),
        route: source.route.clone(),
    });
}

pub(crate) fn prepare(s: &Shared, source: &str, target: &str) -> io::Result<Option<ProfileNames>> {
    let failure = match kernel::prepare_named_active_replacement(&s.store, source, target) {
        Ok(names) => return Ok(names.map(|names| ProfileNames { names, warm: None })),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::ConnectionAborted
            ) =>
        {
            error
        }
        Err(error) => return Err(error),
    };
    let saved = s
        .route_kernel
        .warm_named
        .try_lock()
        .map_err(|_| io::ErrorKind::WouldBlock)?
        .watching
        .as_ref()
        .filter(|watch| watch.profile.source() == source && watch.profile.target() == target)
        .and_then(|watch| {
            Some(WarmConfirmation {
                failure: watch.failure,
                profile: watch.profile.clone(),
                hint: watch.hint.clone()?,
            })
        })
        .ok_or(failure)?;
    saved.verify(s)?;
    // AF_UNSPEC does not identify the failing family. Require the current
    // A-only lookup to fail independently before selecting IPv6.
    saved
        .profile
        .verify_current_ipv4_failure(&s.store, saved.hint.expires)?;
    saved.verify(s)?;
    let names = saved
        .profile
        .authorize(&s.store, &saved.hint.addresses, saved.hint.expires)?;
    Ok(Some(ProfileNames {
        names,
        warm: Some(saved),
    }))
}

pub(super) fn publication(
    s: &Shared,
    result: io::Result<Option<String>>,
) -> io::Result<Option<String>> {
    let written = result
        .as_ref()
        .map(|_| ())
        .map_err(|error| io::Error::new(error.kind(), error.to_string()));
    let outcome = observer::PublicationOutcome::from_result(kernel::Operation::Apply, &written);
    let published = super::publish_observation(s, written, outcome);
    s.route_kernel
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let warning = result?;
    if let Err(error) = published {
        s.logs.append("awg2", "warn", &error.to_string());
        let failure = "перенос сохранён, подтверждение DNS будет повторено";
        return Ok(Some(warning.map_or_else(
            || failure.into(),
            |old| format!("{old}. {failure}"),
        )));
    }
    Ok(warning)
}
