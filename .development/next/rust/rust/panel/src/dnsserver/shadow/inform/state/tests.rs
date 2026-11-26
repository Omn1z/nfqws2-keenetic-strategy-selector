use super::super::elapsed;
use super::*;

const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEW_SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const DNS: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);
const LOCAL: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);
const FALLBACK: Source = Source::Fallback {
    has_verified_peer: false,
};

fn wan(number: u8) -> Wan {
    Wan {
        key: "verified-default".into(),
        iface: format!("ISP{number}"),
        device: format!("eth{number}.2"),
        index: u32::from(number),
        mac: [2, 3, 4, 5, 6, number],
        client: Ipv4Addr::new(192, 0, 2, number + 100),
    }
}

fn known(wan: &Wan, server: Ipv4Addr, observed: i64) -> KnownTarget {
    KnownTarget {
        iface: wan.iface.clone(),
        wan_key: wan.key.clone(),
        client: wan.client,
        server,
        stamp: observed.to_string(),
        observed_at_epoch: Some(observed),
    }
}

fn input(owners: &[Wan], source: Source) -> Input<'_> {
    Input {
        key: "verified-default",
        owners,
        local: &[LOCAL],
        source,
    }
}

fn attempt(plan: Plan) -> Attempt {
    let Plan::Probe(attempt) = plan else {
        panic!("expected an INFORM attempt")
    };
    attempt
}

fn ready(plan: Plan) -> Selection {
    let Plan::Ready(selection) = plan else {
        panic!("unexpected INFORM attempt")
    };
    selection
}

fn options(selection: Selection) -> Options {
    let Selection::Inform(options) = selection else {
        panic!("expected DNS options, got {selection:?}")
    };
    options
}

fn reply(server: Ipv4Addr) -> io::Result<Ack> {
    Ok(Ack {
        server,
        dns: vec![LOCAL, DNS, DNS, Ipv4Addr::LOCALHOST],
    })
}

#[test]
fn initial_broadcast_learns_option54_and_maintains_exact_five_minute_expiry() {
    let mut state = State::default();
    let owners = [wan(2), wan(1)];
    let input = input(&owners, FALLBACK);
    let start = Instant::now();
    let initial = attempt(state.plan(input, start));
    assert_eq!(initial.target().client, owners[0].client);
    assert_eq!(initial.target().server, None);
    let observed = start + Duration::from_millis(400);
    let found = options(state.finish(
        initial,
        reply(SERVER),
        input,
        observed,
        start + Duration::from_secs(2),
    ));
    assert_eq!(found.dns, vec![DNS]);
    assert_eq!(found.expires, observed + VALIDITY);
    assert_eq!(state.known().next().unwrap().server, SERVER);
    assert_eq!(state.known().next().unwrap().client, owners[0].client);
    assert_eq!(
        options(ready(
            state.plan(input, observed + Duration::from_secs(239))
        )),
        found
    );
    let refresh = attempt(state.plan(input, found.expires - REFRESH_MARGIN));
    assert_eq!(refresh.target().server, Some(SERVER));
    assert_eq!(refresh.target().index, owners[0].index);
}

#[test]
fn only_local_reply_timeout_switches_to_verified_broadcast_after_cooldown() {
    let mut state = State::default();
    let owners = [wan(2), wan(1)];
    let context = input(&owners, FALLBACK);
    state.remember(&owners[0], known(&owners[0], NEW_SERVER, 10), context.local);
    state.remember(&owners[1], known(&owners[1], SERVER, 10), context.local);
    let start = Instant::now();
    let first = attempt(state.plan(context, start));
    assert_eq!(first.target().server, Some(SERVER));
    assert_eq!(first.target().client, owners[1].client);
    let ended = start + Duration::from_secs(1);
    assert!(matches!(
        state.finish(first, Err(elapsed(None)), context, ended, ended + BACKOFF),
        Selection::Fallback(Some(_))
    ));
    // A different active WAN may take the next pass, never this one.
    let second = attempt(state.plan(context, ended));
    assert_eq!(second.target().client, owners[0].client);
    let second_result = Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "bounded send failed",
    ));
    state.finish(second, second_result, context, ended, ended + BACKOFF);

    let only_first = input(&owners[1..], FALLBACK);
    assert!(matches!(
        ready(state.plan(only_first, ended + BACKOFF - Duration::from_millis(1))),
        Selection::Fallback(Some(_))
    ));
    let retry = attempt(state.plan(only_first, ended + BACKOFF));
    assert_eq!(retry.target().client, owners[1].client);
    assert_eq!(retry.target().server, None);
    options(state.finish(
        retry,
        reply(NEW_SERVER),
        only_first,
        ended + BACKOFF,
        ended + BACKOFF * 2,
    ));
    let saved = state
        .known()
        .find(|record| record.client == owners[1].client)
        .unwrap();
    assert_eq!((saved.server, saved.stamp.as_str()), (NEW_SERVER, "10"));

    let only_second = input(&owners[..1], FALLBACK);
    let retry_after_send_failure = attempt(state.plan(only_second, ended + BACKOFF));
    assert_eq!(retry_after_send_failure.target().server, Some(NEW_SERVER));
}

#[test]
fn inform_diagnostics_follow_exact_attempt_cache_and_cooldown_branches() {
    let mut state = State::default();
    let owners = [wan(3)];
    let input = input(&owners, FALLBACK);
    let now = Instant::now();
    state.remember(&owners[0], known(&owners[0], SERVER, 10), input.local);
    let mut verified = false;
    let unicast = attempt(state.plan_report(input, now, |event| {
        if let DiscoveryEvent::Target {
            wan,
            server,
            prefer_broadcast,
        } = event
        {
            assert_eq!(wan, &owners[0]);
            assert_eq!(server, SERVER);
            assert!(!prefer_broadcast);
            verified = true;
        }
    }));
    assert!(verified);
    let mut next_mode = false;
    state.finish_report(
        unicast,
        Err(elapsed(None)),
        input,
        now,
        now + BACKOFF,
        |event| {
            if let DiscoveryEvent::NextBroadcast(iface) = event {
                assert_eq!(iface, owners[0].iface);
                next_mode = true;
            }
        },
    );
    assert!(next_mode);
    let mut retry = None;
    assert!(matches!(
        ready(state.plan_report(input, now, |event| {
            if let DiscoveryEvent::Cooldown { next, .. } = event {
                retry = Some(next);
            }
        })),
        Selection::Fallback(Some(_)),
    ));
    assert_eq!(retry, Some(now + BACKOFF));
    let mut mode_changed = false;
    let broadcast = attempt(state.plan_report(input, now + BACKOFF, |event| {
        if let DiscoveryEvent::Broadcast { fallback } = event {
            mode_changed = fallback;
        }
    }));
    assert!(mode_changed);
    let expected = options(state.finish(
        broadcast,
        reply(SERVER),
        input,
        now + BACKOFF,
        now + BACKOFF * 2,
    ));
    let mut reused = false;
    let cached = ready(state.plan_report(input, now + BACKOFF, |event| {
        if let DiscoveryEvent::Cached(options) = event {
            assert_eq!(options, &expected);
            reused = true;
        }
    }));
    assert!(reused);
    assert_eq!(options(cached), expected);
}

#[test]
fn old_log_watermark_cannot_restore_failed_peer_or_reset_positive_cache() {
    let mut state = State::default();
    let owners = [wan(5)];
    let context = input(&owners, FALLBACK);
    let trace = known(&owners[0], SERVER, 10);
    state.remember(&owners[0], trace.clone(), context.local);
    let now = Instant::now();
    let first = attempt(state.plan(context, now));
    state.finish(first, Err(elapsed(None)), context, now, now + BACKOFF);
    let changed = attempt(state.plan(context, now + BACKOFF));
    let fresh = options(state.finish(
        changed,
        reply(NEW_SERVER),
        context,
        now + BACKOFF,
        now + BACKOFF * 2,
    ));
    state.remember(&owners[0], known(&owners[0], SERVER, 9), context.local);
    state.remember(&owners[0], trace, context.local);
    assert_eq!(state.known().next().unwrap().server, NEW_SERVER);
    assert_eq!(options(ready(state.plan(context, now + BACKOFF))), fresh);
    let mut alias = owners[0].clone();
    alias.iface = "GigabitEthernet2".into();
    state.remember(&alias, known(&alias, NEW_SERVER, 11), context.local);
    assert_eq!(state.known().count(), 1);
    assert_eq!(state.known().next().unwrap().iface, owners[0].iface);
    // A later verified renewal refreshes even before the one-minute margin.
    let refresh = attempt(state.plan(context, now + BACKOFF * 2));
    assert_eq!(refresh.target().server, None); // still a known broadcast-only peer
}

#[test]
fn transient_failure_preserves_unexpired_options_without_extending_them() {
    let mut state = State::default();
    let owners = [wan(3)];
    let context = input(&owners, FALLBACK);
    let start = Instant::now();
    let initial = attempt(state.plan(context, start));
    let cached = options(state.finish(initial, reply(SERVER), context, start, start + BACKOFF));
    let refresh_at = cached.expires - REFRESH_MARGIN;
    let refresh = attempt(state.plan(context, refresh_at));
    let before = options(state.finish(
        refresh,
        Err(io::Error::other("transient")),
        context,
        refresh_at,
        refresh_at + BACKOFF,
    ));
    assert_eq!(before, cached);
    assert_eq!(
        options(ready(
            state.plan(context, refresh_at + Duration::from_secs(20))
        )),
        cached
    );
    let final_refresh_at = cached.expires - Duration::from_millis(5);
    let last = attempt(state.plan(context, final_refresh_at));
    assert!(matches!(
        state.finish(
            last,
            Err(io::Error::other("still down")),
            context,
            cached.expires,
            cached.expires + BACKOFF
        ),
        Selection::Fallback(Some(_))
    ));
    assert!(matches!(
        ready(state.plan(context, cached.expires)),
        Selection::Fallback(Some(_))
    ));
}

#[test]
fn canceled_or_superseded_probe_never_creates_cooldown_or_approved_options() {
    let mut state = State::default();
    let owners = [wan(4)];
    let context = input(&owners, FALLBACK);
    let now = Instant::now();
    let first = attempt(state.plan(context, now));
    assert!(
        matches!(state.finish(first, reply(SERVER), context, now, now), Selection::Fallback(Some(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    let second = attempt(state.plan(context, now));
    let replacement = [Wan {
        index: 90,
        ..owners[0].clone()
    }];
    assert!(matches!(
        state.finish(
            second,
            reply(SERVER),
            input(&replacement, FALLBACK),
            now,
            now + BACKOFF
        ),
        Selection::Fallback(None)
    ));
    let third = attempt(state.plan(context, now));
    assert!(matches!(
        state.finish(third, Err(io::ErrorKind::Interrupted.into()), context, now, now + BACKOFF),
        Selection::Fallback(Some(error)) if error.kind() == io::ErrorKind::Interrupted
    ));
    assert_eq!(state.known().count(), 0);
    assert_eq!(attempt(state.plan(context, now)).target().server, None);
}

#[test]
fn native_positive_and_ppp_base_have_independent_precedence() {
    let mut state = State::default();
    let owners = [wan(6)];
    let start = Instant::now();
    assert!(matches!(
        ready(state.plan(input(&owners, Source::Authoritative), start)),
        Selection::Authoritative
    ));
    let ppp = input(
        &owners,
        Source::Fallback {
            has_verified_peer: true,
        },
    );
    assert!(matches!(
        ready(state.plan(ppp, start)),
        Selection::Fallback(None)
    ));
    let otherwise = input(&owners, FALLBACK);
    let known = known(&owners[0], SERVER, 20);
    state.remember(&owners[0], known, otherwise.local);
    let incoming = attempt(state.plan(ppp, start));
    assert_eq!(incoming.target().server, Some(SERVER));
    options(state.finish(incoming, reply(SERVER), ppp, start, start + BACKOFF));
    let native = input(&owners, Source::NativeLease);
    assert!(matches!(
        ready(state.plan(native, start)),
        Selection::NativeLease
    ));
    let mut other = owners[0].clone();
    other.mac[5] = 99;
    state.native_reply(&other);
    assert!(matches!(
        ready(state.plan(otherwise, start)),
        Selection::Inform(_)
    ));
    state.native_reply(&owners[0]); // correlated native ACK/NAK once
    assert!(matches!(
        ready(state.plan(otherwise, start)),
        Selection::Fallback(Some(_))
    ));
    assert_eq!(state.known().count(), 1);
    assert_eq!(
        attempt(state.plan(otherwise, start + BACKOFF))
            .target()
            .server,
        Some(SERVER)
    );
}

#[test]
fn eligible_targets_and_acks_are_bounded_and_cannot_follow_router_dns_loop() {
    let mut state = State::default();
    let owners: Vec<_> = (1..=9).map(wan).collect();
    let context = input(&owners, FALLBACK);
    for owner in &owners {
        state.remember(owner, known(owner, owner.client, 11), context.local);
        state.remember(owner, known(owner, LOCAL, 11), context.local);
    }
    assert_eq!(state.known().count(), 0);
    let now = Instant::now();
    let broadcast = attempt(state.plan(context, now));
    assert!(matches!(
        state.finish(broadcast, reply(LOCAL), context, now, now + BACKOFF),
        Selection::Fallback(Some(error)) if error.kind() == io::ErrorKind::InvalidData
    ));
    assert_eq!(state.known().count(), 0);
    assert!(matches!(
        ready(state.plan(context, now)),
        Selection::Fallback(Some(_))
    ));
    for owner in &owners {
        state.remember(owner, known(owner, SERVER, 12), context.local);
    }
    assert_eq!(state.known().count(), LIMIT);
    let next = attempt(state.plan(context, now + BACKOFF));
    let dns: Vec<_> = (1..=10)
        .map(|end| Ipv4Addr::new(198, 51, 100, end))
        .collect();
    let expected = dns[..LIMIT].to_vec();
    let gained = options(state.finish(
        next,
        Ok(Ack {
            server: SERVER,
            dns,
        }),
        context,
        now + BACKOFF,
        now + BACKOFF * 2,
    ));
    assert_eq!(gained.dns, expected);
}

#[test]
fn known_probe_and_directed_broadcast_require_the_same_attested_alias() {
    let mut state = State::default();
    let canonical = wan(4);
    let alias = Wan {
        iface: "ISP-prior".into(),
        ..canonical.clone()
    };
    let both = [canonical.clone(), alias.clone()];
    let attested = input(&both, FALLBACK);
    state.remember(&alias, known(&alias, SERVER, 10), attested.local);
    let now = Instant::now();
    let direct = attempt(state.plan(attested, now));
    assert_eq!(direct.wan(), &alias);
    assert_eq!(direct.target().server, Some(SERVER));
    state.finish(direct, Err(elapsed(None)), attested, now, now + BACKOFF);

    let retry_at = now + BACKOFF;
    let directed = attempt(state.plan(attested, retry_at));
    assert_eq!(directed.wan(), &alias);
    assert_eq!(directed.target().server, None);
    let found = options(state.finish(
        directed,
        reply(NEW_SERVER),
        attested,
        retry_at,
        retry_at + BACKOFF,
    ));
    assert_eq!(found.wan, alias);
    assert_eq!(state.known().next().unwrap().iface, alias.iface);

    // With the native alias no longer verified, the same MAC and address
    // alone may admit a new broadcast, never the stale known peer or cache.
    let only_canonical = std::slice::from_ref(&canonical);
    let verified_ppp = input(
        only_canonical,
        Source::Fallback {
            has_verified_peer: true,
        },
    );
    assert!(matches!(
        ready(state.plan(verified_ppp, retry_at)),
        Selection::Fallback(None)
    ));
    let unknown_context = input(only_canonical, FALLBACK);
    let unknown = attempt(state.plan(unknown_context, retry_at));
    assert_eq!(unknown.wan(), &canonical);
    assert_eq!(unknown.target().server, None);
    options(state.finish(
        unknown,
        reply(SERVER),
        unknown_context,
        retry_at,
        retry_at + BACKOFF,
    ));
    let records: Vec<_> = state.known().collect();
    assert_eq!(records.len(), 1);
    assert_eq!(
        (&records[0].iface, records[0].server),
        (&canonical.iface, SERVER)
    );
}

#[test]
fn failed_first_unicast_reuses_only_a_later_verified_warm_or_cooled_answer() {
    for (label, to_expiry, cool_later, retain_alias, expect_cache) in [
        ("warm", 90, false, true, true),
        ("cooling", 20, true, true, true),
        ("due", 20, false, true, false),
        ("expired", 0, false, true, false),
        ("unsafe alias", 90, false, false, false),
    ] {
        let mut state = State::default();
        let owners = [wan(2), wan(1)];
        let context = input(&owners, FALLBACK);
        let later_only = input(&owners[..1], FALLBACK);
        let now = Instant::now();
        state.remember(&owners[0], known(&owners[0], NEW_SERVER, 20), context.local);
        let seed = attempt(state.plan(later_only, now));
        let cached = options(state.finish(seed, reply(NEW_SERVER), later_only, now, now + BACKOFF));
        let now = cached.expires - Duration::from_secs(to_expiry);
        if cool_later {
            let later = attempt(state.plan(later_only, now));
            assert_eq!(later.wan(), &owners[0]);
            options(state.finish(
                later,
                Err(io::Error::other("later peer was briefly unavailable")),
                later_only,
                now,
                now + BACKOFF,
            ));
        }
        state.remember(&owners[1], known(&owners[1], SERVER, 20), context.local);
        let unicast = attempt(state.plan(context, now));
        assert_eq!(unicast.wan(), &owners[1]);
        let mut latest = owners.clone();
        if !retain_alias {
            latest[0].iface = "unrelated-native-alias".into();
        }
        let actual = state.finish(
            unicast,
            Err(elapsed(None)),
            input(&latest, FALLBACK),
            now + Duration::from_millis(1),
            now + BACKOFF,
        );
        if expect_cache {
            assert_eq!(options(actual), cached, "{label}");
        } else {
            assert!(
                matches!(actual, Selection::Fallback(Some(_))),
                "{label}: {actual:?}"
            );
        }
    }
}
