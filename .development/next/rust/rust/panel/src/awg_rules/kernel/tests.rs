use super::*;
use futures_util::FutureExt;
use std::net::Ipv4Addr;
use std::sync::Mutex;

#[tokio::test]
async fn dormant_profile_rearm_wakes_an_idle_route_worker() {
    let root = tempfile::tempdir().unwrap();
    let service = Arc::new(Service::new(root.path()));
    let (sender, mut idle) = watch::channel(0);
    *service.worker.lock().await = Some((sender, tokio::spawn(async {})));
    assert!(!idle.has_changed().unwrap());
    let change = service.clone();
    tokio::task::spawn_blocking(move || change.notify_rearm())
        .await
        .unwrap();
    assert!(idle.has_changed().unwrap());
    assert_eq!(*idle.borrow_and_update(), service.generation.load(Ordering::Acquire));
    assert_eq!(*idle.borrow(), 1);
}

#[tokio::test]
async fn watchdog_waits_until_its_first_minute_and_skips_missed_ticks() {
    let mut clock = legacy_watchdog_interval();
    assert_eq!(clock.period(), Duration::from_secs(60));
    assert_eq!(clock.missed_tick_behavior(), MissedTickBehavior::Skip);
    assert!(clock.tick().now_or_never().is_none());
}

fn names(count: usize) -> DnsRequest {
    DnsRequest {
        revision: 42,
        dual_stack: vec![],
        ipv6_only: vec![],
        names: (1..=count).map(|i| format!("host{i}.example")).collect(),
    }
}

#[test]
fn complete_snapshot_keeps_revision_names_and_a_single_deadline() {
    let servers = [SocketAddr::from(([127, 0, 0, 1], 5354))];
    for count in [1, 3, 4, 32] {
        let start = Instant::now();
        let observations = Mutex::new(Vec::new());
        let request = names(count);
        let snapshot = resolve_names(
            request.clone(),
            &servers,
            start + DNS_BUDGET,
            |name, actual, deadline, _, _| {
                assert_eq!(actual, servers);
                let index: u8 = name[4..].split('.').next().unwrap().parse().unwrap();
                observations
                    .lock()
                    .unwrap()
                    .push((std::thread::current().id(), deadline));
                Ok(vec![Ipv4Addr::new(192, 0, 2, index).into()])
            },
        )
        .unwrap();
        assert_eq!(snapshot.request, request);
        assert_eq!(snapshot.answers.len(), count);
        for (i, name) in request.names.iter().enumerate() {
            assert_eq!(
                snapshot.answers[name],
                [Ipv4Addr::new(192, 0, 2, (i + 1) as u8)]
            );
        }
        let observations = observations.into_inner().unwrap();
        let deadline = observations[0].1;
        let threads: std::collections::HashSet<_> = observations.iter().map(|v| v.0).collect();
        assert_eq!(threads.len(), if count < 4 { 1 } else { 2 });
        assert!(deadline >= start + DNS_BUDGET && deadline <= Instant::now() + DNS_BUDGET);
        assert!(observations.iter().all(|v| v.1 == deadline));
    }
}

#[test]
fn either_group_failing_discards_the_entire_snapshot() {
    for fail in ["host1.example", "host4.example"] {
        let error = resolve_names(
            names(4),
            &[],
            Instant::now() + DNS_BUDGET,
            |name, _, _, _, _| {
                if name == fail {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(vec![Ipv4Addr::new(192, 0, 2, 10).into()])
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains(fail));
    }
}

#[test]
fn reused_snapshot_deadline_does_not_start_another_lookup() {
    let error = resolve_names(names(1), &[], Instant::now(), |_, _, _, _, _| {
        panic!("the earlier preparation already spent the lookup budget")
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn profile_transition_holds_route_lock_and_busy_watchdog_defers() {
    let root = tempfile::tempdir().unwrap();
    let cfg = nfqws2_config::Config::from_resolver(&nfqws2_config::Resolver::new_at(root.path()));
    let state = crate::http::AppState::open(cfg, root.path(), true).unwrap();
    let saved = change_profile(&state, || {
        assert!(state.route_kernel.operations.try_lock().is_err());
        assert!(retry_profiles::<Vec<String>>(&state, || {
            panic!("profile watchdog raced route edit")
        })?
        .is_empty());
        Ok("saved")
    })
    .unwrap();
    assert_eq!(saved, "saved");
    assert_eq!(
        retry_profiles::<Vec<String>>(&state, || {
            assert!(state.route_kernel.operations.try_lock().is_err());
            Ok(vec!["retried".into()])
        })
        .unwrap(),
        ["retried"]
    );
}
