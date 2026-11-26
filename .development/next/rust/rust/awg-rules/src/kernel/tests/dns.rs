use super::*;
use std::net::Ipv4Addr;

fn fixture(killswitch: bool) -> (tempfile::TempDir, Store, Fake) {
    let (temp, db, f) = setup();
    scoped_policy(&db);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["killswitch"] = json!(killswitch);
        doc["routing"]["domain_source"] = json!("resolve");
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[1]["config"]["routing"]["zones"] = json!([]);
        rows[0]["config"]["routing"]["zones"] = json!([
            {"order":1,"enabled":true,"route":"direct","include_subdomains":false,"domains":["skip.example.test"],"source_ips":["192.168.1.7"]},
            {"order":2,"enabled":true,"route":"tunnel","include_subdomains":false,"domains":["FULL:Office.Example.Test.","office.example.test","DoMaiN:OFFICE.example.test."],
            "ips":["203.0.113.200"],"source_ips":["192.168.1.0/24"],"fallback_tunnel_ids":["branch"]}
        ]);
        Ok(())
    }).unwrap();
    f.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    (temp, db, f)
}

fn snapshot(db: &Store, op: Operation, extra: &str) -> DnsSnapshot {
    // Old Rust installations can have committed eager snapshots for a
    // source-bound zone. Recreate their request to exercise rotation on upgrade.
    let request = dns_request(db, op).unwrap().unwrap_or_else(|| {
        assert!(matches!(op, Operation::Apply));
        let doc = nfqws2_awg_profile::read(db).unwrap();
        crate::kernel::dns::exact_request(
            &crate::policy::current(&doc).unwrap(),
            doc["routing_revision"].as_u64().unwrap(),
            &doc,
        )
        .unwrap()
        .unwrap()
    });
    assert_eq!(request.names, ["office.example.test", "skip.example.test"]);
    let answers = BTreeMap::from([
        (
            "office.example.test".into(),
            vec!["203.0.113.9".parse().unwrap(), extra.parse().unwrap()],
        ),
        (
            "skip.example.test".into(),
            vec!["203.0.113.9".parse().unwrap()],
        ),
    ]);
    DnsSnapshot { request, answers }
}
fn operate_dns(
    db: &Store,
    f: &Fake,
    op: Operation,
    snapshot: Option<&DnsSnapshot>,
    up: [bool; 2],
) -> io::Result<()> {
    operate_with_dns_at(db, f, op, nfqws2_awg_profile::now(), snapshot, |c, i| {
        if !up[usize::from(i == "awg1")] {
            return Err(io::ErrorKind::NotConnected.into());
        }
        both_peers(c, i)
    })
}
fn confirm(db: &Store, f: &Fake) -> DnsSnapshot {
    let dns = snapshot(db, Operation::Apply, "203.0.113.8");
    assert!(needs_dns_listener(db).unwrap());
    operate_dns(db, f, Operation::Apply, Some(&dns), [true; 2]).unwrap();
    assert!(matches!(scheduled(db).unwrap(), Schedule::Expires(_)));
    assert!(dns_request(db, Operation::Commit).unwrap().is_none());
    operate_dns(db, f, Operation::Commit, None, [true; 2]).unwrap();
    assert_eq!(scheduled(db).unwrap(), Schedule::Dns);
    dns
}
fn forward(f: &Fake, src: &str, dest: &str) -> String {
    f.0.lock().unwrap().forward(src, dest).into()
}
const LAN: &str = "192.168.1.7";
const OLD: &str = "203.0.113.8";
const NEW: &str = "203.0.113.42";
const COMMON: &str = "203.0.113.200";

fn cold_retry_fixture() -> (tempfile::TempDir, Store, Fake, DnsSnapshot) {
    let (dir, db, router) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["domain_source"] = json!("resolve");
        doc["servers"][0]["config"]["routing"]["zones"] = json!([{
            "enabled":true,"domains":["office.example.test"],"include_subdomains":false,
            "ips":[COMMON]
        }]);
        Ok(())
    })
    .unwrap();
    let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
    let snapshot = DnsSnapshot {
        request,
        answers: [("office.example.test".into(), vec![OLD.parse().unwrap()])].into(),
    };
    (dir, db, router, snapshot)
}

fn confirmed_retry_fixture() -> (tempfile::TempDir, Store, Fake, DnsSnapshot) {
    let (dir, db, router, snapshot) = cold_retry_fixture();
    let now = nfqws2_awg_profile::now();
    operate_with_dns_at(&db, &router, Operation::Apply, now, Some(&snapshot), peer).unwrap();
    operate_at(&db, &router, Operation::Commit, now, peer).unwrap();
    (dir, db, router, snapshot)
}

struct ColdRouter<'a> {
    router: &'a Fake,
    fail_route: std::sync::atomic::AtomicBool,
    foreign_v6: std::sync::atomic::AtomicBool,
    add_foreign_after_failure: bool,
}

impl<'a> ColdRouter<'a> {
    fn new(router: &'a Fake) -> Self {
        Self {
            router,
            fail_route: false.into(),
            foreign_v6: false.into(),
            add_foreign_after_failure: false,
        }
    }
}

impl Runner for ColdRouter<'_> {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        use std::sync::atomic::Ordering::Relaxed;

        if program == "sh" && matches!(args, ["-c", script] if script.contains("91-awg2-multi.sh"))
        {
            let capabilities = self.router.run(program, args, deadline)?;
            return Ok(format!("ipv6\n{capabilities}"));
        }
        match (program, args) {
            ("ip", ["-o", "-N", "-6", "rule", "show"]) => Ok(String::new()),
            ("ip", ["-o", "-N", "-6", "route", "show", "table", "all"]) => {
                Ok(if self.foreign_v6.load(Relaxed) {
                    "7 2001:db8:72::/64 table 17842 proto 186 metric 1024 pref 0"
                } else {
                    ""
                }
                .into())
            }
            ("ip", ["-4", "route", "add", "table", "17842", ..])
                if self.fail_route.swap(false, Relaxed) =>
            {
                self.router.run(program, args, deadline)?;
                if self.add_foreign_after_failure {
                    self.foreign_v6.store(true, Relaxed);
                }
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "first route accepted",
                ))
            }
            _ => self.router.run(program, args, deadline),
        }
    }
}

#[test]
fn cold_static_dns_apply_retries_exact_empty_boot_then_uses_ordinary_trials() {
    use std::sync::atomic::Ordering::Relaxed;

    let (_dir, db, fake, snapshot) = cold_retry_fixture();
    let router = ColdRouter::new(&fake);
    let draft = cold_static_dns_draft(&db, &router, &snapshot.request)
        .unwrap()
        .unwrap();
    assert_eq!(draft.request(), &snapshot.request);
    assert_eq!(Journal::read(&db).unwrap(), Journal::default());
    let baseline = Journal {
        boot: BOOT.into(),
        ..Default::default()
    };
    let fail_then_retry = || {
        router.fail_route.store(true, Relaxed);
        let failure = apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Cold(&draft, &snapshot),
            peer,
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(failure.to_string(), "first route accepted");
        let ticket = failed_static_dns_apply(&failure).unwrap();
        assert!(ticket.baseline().is_none());
        assert_eq!(ticket.cold_draft(), Some(&draft));
        assert_eq!(ticket.snapshot(), &snapshot);
        assert_eq!(Journal::read(&db).unwrap(), baseline);
        assert!(nfqws2_awg_profile::read(&db).unwrap()["rust_static_routing"].is_null());
        assert_eq!(path(&fake, OLD), "wan0");
        assert_eq!(path(&fake, COMMON), "wan0");
        assert_eq!(
            cold_static_dns_draft(&db, &router, &snapshot.request).unwrap(),
            Some(draft.clone())
        );

        let retry = || {
            apply_managed_static_dns_proposal(
                &db,
                &router,
                ManagedStaticDnsApply::Retry(ticket),
                peer,
                || Ok(()),
            )
        };
        router.foreign_v6.store(true, Relaxed);
        assert!(cold_static_dns_draft(&db, &router, &snapshot.request).is_err());
        assert!(failed_static_dns_apply(&retry().unwrap_err()).is_none());
        router.foreign_v6.store(false, Relaxed);
        fake.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
        assert!(failed_static_dns_apply(&retry().unwrap_err()).is_none());
        fake.0.lock().unwrap().boot = BOOT.into();
        assert_eq!(Journal::read(&db).unwrap(), baseline);

        retry().unwrap();
        let trial = Journal::read(&db).unwrap();
        assert_eq!(trial.committed, baseline.committed);
        assert_eq!(trial.installed.dns.as_ref().unwrap().snapshot, snapshot);
        assert!(trial.expires > nfqws2_awg_profile::now());
        assert!(cold_static_dns_draft(&db, &router, &snapshot.request)
            .unwrap()
            .is_none());
        assert_eq!(path(&fake, OLD), "awg0");
        assert_eq!(path(&fake, COMMON), "awg0");
        trial.expires
    };

    let expires = fail_then_retry();
    operate_at(&db, &router, Operation::Recover, expires + 1, peer).unwrap();
    assert_eq!(Journal::read(&db).unwrap(), baseline);
    fail_then_retry();
    operate(&db, &router, Operation::Commit, peer).unwrap();
    let committed = Journal::read(&db).unwrap();
    assert_eq!(committed.expires, 0);
    assert_eq!(committed.committed.dns.as_ref().unwrap().snapshot, snapshot);
}

#[test]
fn cold_static_dns_apply_requires_unchanged_wire_and_budget_without_a_prior_owner() {
    let (_dir, db, fake, snapshot) = cold_retry_fixture();
    let router = ColdRouter::new(&fake);
    let read = || cold_static_dns_draft(&db, &router, &snapshot.request);
    let draft = read().unwrap().unwrap();
    assert_eq!(
        cold_static_dns_draft_until(&db, &router, &snapshot.request, Instant::now())
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        db.transaction(|_| read().map(|_| ())).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    for expires_at in [3, 4] {
        let calls = Cell::new(0);
        let expired = apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Cold(&draft, &snapshot),
            peer,
            || {
                calls.set(calls.get() + 1);
                if calls.get() >= expires_at {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(expired.kind(), io::ErrorKind::TimedOut);
        assert!(failed_static_dns_apply(&expired).is_none());
        assert_eq!(Journal::read(&db).unwrap(), Journal::default());
        assert_eq!(fake.0.lock().unwrap().changes, 0);
    }
    let original = nfqws2_awg_profile::read(&db).unwrap();
    for fields in [["client_iface", "awg53"], ["endpoint", "198.51.100.50:443"]] {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            *doc = original.clone();
            doc["servers"][0]["config"][fields[0]] = json!(fields[1]);
            Ok(())
        })
        .unwrap();
        assert_ne!(read().unwrap().unwrap(), draft);
        assert!(apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Cold(&draft, &snapshot),
            |_, _| panic!("changed draft must fail before reading a peer"),
            || Ok(()),
        )
        .is_err());
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        *doc = original;
        doc["servers"][0]["config"]["routing"]["active"] = json!(true);
        Ok(())
    })
    .unwrap();
    assert!(read().unwrap().is_none());
    assert_eq!(Journal::read(&db).unwrap(), Journal::default());
    assert_eq!(fake.0.lock().unwrap().changes, 0);
}

#[test]
fn cold_static_dns_apply_requires_both_families_still_empty_after_compensation() {
    use std::sync::atomic::Ordering::Relaxed;

    let (_dir, db, fake, snapshot) = cold_retry_fixture();
    let router = ColdRouter {
        add_foreign_after_failure: true,
        ..ColdRouter::new(&fake)
    };
    let draft = cold_static_dns_draft(&db, &router, &snapshot.request)
        .unwrap()
        .unwrap();
    router.fail_route.store(true, Relaxed);
    let failed = apply_managed_static_dns_proposal(
        &db,
        &router,
        ManagedStaticDnsApply::Cold(&draft, &snapshot),
        peer,
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(failed.kind(), io::ErrorKind::BrokenPipe);
    assert!(failed_static_dns_apply(&failed).is_none());
    assert!(Journal::read(&db).unwrap().cold_empty());
    assert!(router.foreign_v6.load(Relaxed));
    assert_eq!(path(&fake, OLD), "wan0");
}

fn managed_rotation(db: &Store, snapshot: &DnsSnapshot) -> (ConfirmedStaticDnsRetry, DnsSnapshot) {
    let baseline = confirmed_static_dns_retry(db, &snapshot.request)
        .unwrap()
        .unwrap();
    let mut proposed = snapshot.clone();
    proposed.answers.get_mut("office.example.test").unwrap()[0] = NEW.parse().unwrap();
    (baseline, proposed)
}

#[test]
fn managed_static_refresh_requires_the_exact_installed_confirmed_snapshot() {
    let (_dir, db, router, before) = confirmed_retry_fixture();
    let (_, fresh) = managed_rotation(&db, &before);
    let now = nfqws2_awg_profile::now();
    let installed = |snapshot| installed_static_dns_snapshot(&db, snapshot).unwrap();
    assert!(installed(&before));
    assert!(!installed(&fresh));

    operate_at(&db, &router, Operation::Refresh, now, peer).unwrap();
    assert!(!installed(&fresh));
    assert_eq!(path(&router, OLD), "awg0");
    assert_eq!(path(&router, NEW), "wan0");

    operate_with_dns_at(&db, &router, Operation::Refresh, now, Some(&fresh), peer).unwrap();
    assert!(installed(&fresh));
    assert!(!installed(&before));
    assert_eq!(path(&router, NEW), "awg0");

    operate_with_dns_at(&db, &router, Operation::Apply, now, Some(&before), peer).unwrap();
    operate_with_dns_at(&db, &router, Operation::Refresh, now, Some(&before), peer).unwrap();
    assert!(
        !installed(&before),
        "an unconfirmed trial must not prove a refresh"
    );
    assert!(!installed(&fresh));
    operate_at(&db, &router, Operation::Commit, now, peer).unwrap();
    assert!(installed(&before));
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing_revision"] = json!(before.request.revision + 1);
        Ok(())
    })
    .unwrap();
    assert!(!installed(&before));
}

#[test]
fn managed_static_dns_rotation_requires_a_compensated_writer_and_uses_normal_trials() {
    let (_dir, db, router, snapshot) = confirmed_retry_fixture();
    let (baseline, proposed) = managed_rotation(&db, &snapshot);
    let old = Journal::read(&db).unwrap();
    let fail_then_retry = || {
        {
            let mut firmware = router.0.lock().unwrap();
            firmware.fail_after = Some(firmware.changes + 2);
        }
        let failure = apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Fresh(&baseline, &proposed),
            peer,
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::Other);
        assert_eq!(
            failure.to_string(),
            "injected error after kernel accepted command"
        );
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(path(&router, OLD), "awg0");
        assert_eq!(path(&router, NEW), "wan0");
        let ticket = failed_static_dns_apply(&failure).unwrap();
        assert_eq!(ticket.snapshot(), &proposed);
        assert_eq!(ticket.baseline(), Some(&baseline));

        let set_mtu = |mtu| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["servers"][0]["config"]["mtu"] = json!(mtu);
                Ok(())
            })
            .unwrap();
        };
        let before = nfqws2_awg_profile::read(&db).unwrap();
        set_mtu(1300);
        let changes = router.0.lock().unwrap().changes;
        let rejected = apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Retry(ticket),
            |_, _| panic!("changed targets must fail before reading live peers"),
            || Ok(()),
        )
        .unwrap_err();
        assert!(failed_static_dns_apply(&rejected).is_none());
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(router.0.lock().unwrap().changes, changes);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            *doc = before;
            Ok(())
        })
        .unwrap();

        apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Retry(ticket),
            peer,
            || Ok(()),
        )
        .unwrap();
        let trial = Journal::read(&db).unwrap();
        assert_eq!(trial.committed, old.committed);
        assert!(trial.preparing.is_empty());
        assert!(trial.expires >= nfqws2_awg_profile::now());
        assert_eq!(trial.installed.dns.as_ref().unwrap().snapshot, proposed);
        assert_eq!(path(&router, OLD), "wan0");
        assert_eq!(path(&router, NEW), "awg0");
        assert_eq!(path(&router, COMMON), "awg0");
        trial.expires
    };

    let expires = fail_then_retry();
    operate_at(&db, &router, Operation::Recover, expires + 1, peer).unwrap();
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(path(&router, OLD), "awg0");
    assert_eq!(path(&router, NEW), "wan0");
    fail_then_retry();
    operate(&db, &router, Operation::Commit, peer).unwrap();
    let committed = Journal::read(&db).unwrap();
    assert_eq!(committed.expires, 0);
    assert_eq!(committed.committed.dns.as_ref().unwrap().snapshot, proposed);
}

#[test]
fn managed_static_dns_rotation_never_issues_a_proposal_for_expiry_or_preflight() {
    struct RefuseRouteChanges<'a>(&'a Fake);
    impl Runner for RefuseRouteChanges<'_> {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if program == "ip" && matches!(args, ["-4", "rule", "del", "pref", "68", "table", ..]) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "kernel not reached",
                ));
            }
            self.0.run(program, args, deadline)
        }
    }

    let (_dir, db, router, snapshot) = confirmed_retry_fixture();
    let (baseline, proposed) = managed_rotation(&db, &snapshot);
    let old = Journal::read(&db).unwrap();
    let writes = router.0.lock().unwrap().changes;

    let same = apply_managed_static_dns_proposal(
        &db,
        &router,
        ManagedStaticDnsApply::Fresh(&baseline, &snapshot),
        |_, _| panic!("no rotation to inspect"),
        || Ok(()),
    )
    .unwrap_err();
    assert!(managed_static_dns_proposal_off_scope(&same));
    assert!(failed_static_dns_apply(&same).is_none());
    assert!(!managed_static_dns_proposal_off_scope(
        &io::ErrorKind::Unsupported.into()
    ));

    router.0.lock().unwrap().local = "2: br0 inet 192.168.1.1/24 scope global".into();
    let mut foreign = proposed.clone();
    foreign.answers.get_mut("office.example.test").unwrap()[0] = "192.168.1.7".parse().unwrap();
    let blocked = apply_managed_static_dns_proposal(
        &db,
        &router,
        ManagedStaticDnsApply::Fresh(&baseline, &foreign),
        peer,
        || Ok(()),
    )
    .unwrap_err();
    assert!(failed_static_dns_apply(&blocked).is_none());
    assert!(!managed_static_dns_proposal_off_scope(&blocked));
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(router.0.lock().unwrap().changes, writes);

    let unwritten = apply_managed_static_dns_proposal(
        &db,
        &RefuseRouteChanges(&router),
        ManagedStaticDnsApply::Fresh(&baseline, &proposed),
        peer,
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(unwritten.kind(), io::ErrorKind::Unsupported);
    assert!(failed_static_dns_apply(&unwritten).is_none());
    assert!(!managed_static_dns_proposal_off_scope(&unwritten));
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(router.0.lock().unwrap().changes, writes);

    for expires_at in [3, 4] {
        let calls = Cell::new(0);
        let before = router.0.lock().unwrap().changes;
        let expired = apply_managed_static_dns_proposal(
            &db,
            &router,
            ManagedStaticDnsApply::Fresh(&baseline, &proposed),
            peer,
            || {
                calls.set(calls.get() + 1);
                if calls.get() >= expires_at {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(expired.kind(), io::ErrorKind::TimedOut);
        assert!(failed_static_dns_apply(&expired).is_none());
        assert_eq!(calls.get(), expires_at);
        assert_eq!(router.0.lock().unwrap().changes == before, expires_at == 3);
        assert_eq!(Journal::read(&db).unwrap(), old);
        assert_eq!(path(&router, OLD), "awg0");
        assert_eq!(path(&router, NEW), "wan0");
    }
}

#[test]
fn managed_static_dns_rotation_with_failed_compensation_has_no_retry_authority() {
    struct BrokenRollback<'a>(&'a Fake);
    impl Runner for BrokenRollback<'_> {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if program == "ip" && matches!(args, ["-4", "rule", "add", "pref", "68", "table", ..]) {
                return Err(io::Error::other("injected failed compensation"));
            }
            self.0.run(program, args, deadline)
        }
    }

    let (_dir, db, router, snapshot) = confirmed_retry_fixture();
    let (baseline, proposed) = managed_rotation(&db, &snapshot);
    let old = Journal::read(&db).unwrap();
    {
        let mut firmware = router.0.lock().unwrap();
        firmware.fail_after = Some(firmware.changes + 2);
    }
    let failure = apply_managed_static_dns_proposal(
        &db,
        &BrokenRollback(&router),
        ManagedStaticDnsApply::Fresh(&baseline, &proposed),
        peer,
        || Ok(()),
    )
    .unwrap_err();
    assert!(failure.to_string().contains("injected failed compensation"));
    assert!(failed_static_dns_apply(&failure).is_none());
    let interrupted = Journal::read(&db).unwrap();
    assert_eq!(interrupted.committed, old.committed);
    assert!(!interrupted.preparing.is_empty());
    operate(&db, &router, Operation::Recover, peer).unwrap();
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(path(&router, OLD), "awg0");
    assert_eq!(path(&router, NEW), "wan0");
}

#[test]
fn static_dns_retry_rechecks_live_freshness_before_the_normal_writer() {
    let (_dir, db, router, snapshot) = confirmed_retry_fixture();
    let ticket = confirmed_static_dns_retry(&db, &snapshot.request)
        .unwrap()
        .unwrap();
    assert_eq!(ticket.snapshot(), &snapshot);
    let baseline = Journal::read(&db).unwrap();
    let writes = router.0.lock().unwrap().changes;
    let calls = std::cell::Cell::new(0);
    let apply = apply_confirmed_static_dns_retry(&db, &router, &ticket, peer, || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    });
    assert_eq!(apply.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls.get(), 2);
    assert_eq!(Journal::read(&db).unwrap(), baseline);
    assert_eq!(router.0.lock().unwrap().changes, writes);
    assert_eq!(path(&router, OLD), "awg0");
    assert_eq!(path(&router, NEW), "wan0");

    router.0.lock().unwrap().boot = "34343434-3434-3434-3434-343434343434".into();
    assert!(
        apply_confirmed_static_dns_retry(&db, &router, &ticket, peer, || {
            panic!("a stale boot has no static retry authority")
        })
        .is_err()
    );
    assert_eq!(Journal::read(&db).unwrap(), baseline);
    assert_eq!(router.0.lock().unwrap().changes, writes);
    router.0.lock().unwrap().boot = BOOT.into();
    assert!(apply_confirmed_static_dns_retry(
        &db,
        &router,
        &ticket,
        |_, _| { Err(io::ErrorKind::NotConnected.into()) },
        || Ok(())
    )
    .is_err());
    assert_eq!(Journal::read(&db).unwrap(), baseline);
    assert_eq!(router.0.lock().unwrap().changes, writes);

    apply_confirmed_static_dns_retry(&db, &router, &ticket, peer, || Ok(())).unwrap();
    let trial = Journal::read(&db).unwrap();
    assert_eq!(trial.committed, baseline.committed);
    assert_eq!(trial.installed.dns, baseline.installed.dns);
    assert!(trial.expires > 0);
    assert_eq!(path(&router, OLD), "awg0");
    assert_eq!(path(&router, NEW), "wan0");
    assert!(confirmed_static_dns_retry(&db, &snapshot.request)
        .unwrap()
        .is_none());
}

#[test]
fn static_dns_retry_rejects_draft_source_target_and_committed_answer_drift() {
    let (_dir, db, router, snapshot) = confirmed_retry_fixture();
    let ticket = confirmed_static_dns_retry(&db, &snapshot.request)
        .unwrap()
        .unwrap();
    let baseline = Journal::read(&db).unwrap();
    let original = nfqws2_awg_profile::read(&db).unwrap();
    let writes = router.0.lock().unwrap().changes;
    let rejected = || {
        assert!(apply_confirmed_static_dns_retry(
            &db,
            &router,
            &ticket,
            |_, _| { panic!("changed geometry must be rejected before peer verification") },
            || panic!("changed geometry has no resolver receipt")
        )
        .is_err());
        assert_eq!(router.0.lock().unwrap().changes, writes);
    };
    let mut wrong_family = snapshot.request.clone();
    wrong_family.dual_stack.clone_from(&wrong_family.names);
    assert!(confirmed_static_dns_retry(&db, &wrong_family)
        .unwrap()
        .is_none());
    let mut wrong_name = snapshot.request.clone();
    wrong_name.names[0] = "other.example.test".into();
    assert!(confirmed_static_dns_retry(&db, &wrong_name)
        .unwrap()
        .is_none());
    let mut newer = snapshot.request.clone();
    newer.revision += 1;
    assert!(confirmed_static_dns_retry(&db, &newer).unwrap().is_none());
    let edits: [fn(&mut Value); 4] = [
        |doc: &mut Value| doc["servers"][0]["config"]["routing"]["zones"][0]["ips"] = json!([NEW]),
        |doc: &mut Value| {
            doc["servers"][0]["config"]["routing"]["zones"][0]["source_ips"] = json!([LAN])
        },
        |doc: &mut Value| {
            doc["servers"][0]["config"]["public_key"] =
                json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
        },
        |doc: &mut Value| doc["servers"][0]["rust_pending_client_profile"] = json!([]),
    ];
    for edit in edits {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            edit(doc);
            Ok(())
        })
        .unwrap();
        assert!(confirmed_static_dns_retry(&db, &snapshot.request)
            .unwrap()
            .is_none());
        rejected();
        assert_eq!(Journal::read(&db).unwrap(), baseline);
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc.clone_from(&original);
            Ok(())
        })
        .unwrap();
    }

    let mut rotated = baseline.clone();
    for plan in [&mut rotated.committed, &mut rotated.installed] {
        plan.dns
            .as_mut()
            .unwrap()
            .snapshot
            .answers
            .insert("office.example.test".into(), vec![NEW.parse().unwrap()]);
    }
    db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &rotated, RECEIPT_LIMIT))
        .unwrap();
    rejected();
    assert_eq!(Journal::read(&db).unwrap(), rotated);
}

#[test]
fn static_dns_retry_requires_complete_positive_answers_in_every_requested_family() {
    use super::ipv6::Dual;

    const V4_NAME: &str = "v4.example.test";
    const DUAL_NAME: &str = "dual.example.test";
    const V6_NAME: &str = "v6.example.test";
    const V4_HOSTS: [&str; 2] = ["203.0.113.11", "203.0.113.12"];
    const DUAL_V4_HOST: &str = "203.0.113.21";
    const DUAL_V6_HOSTS: [&str; 2] = ["2001:db8:70::21", "2001:db8:70::22"];
    const V6_HOSTS: [&str; 2] = ["2001:db8:70::31", "2001:db8:70::32"];
    for complete in [false, true] {
        let (_dir, db, _) = setup();
        let router = Dual::default();
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"]["domain_source"] = json!("resolve");
            let rows = doc["servers"].as_array_mut().unwrap();
            let template = rows[0].clone();
            for (index, (name, addresses, grants)) in [
                (V4_NAME, "10.70.0.2/32", "0.0.0.0/0"),
                (
                    DUAL_NAME,
                    "10.71.0.2/32,2001:db8:71::2/128",
                    "0.0.0.0/0,::/0",
                ),
                (V6_NAME, "2001:db8:72::2/128", "::/0"),
            ]
            .into_iter()
            .enumerate()
            {
                if index != 0 {
                    let mut row = template.clone();
                    row["id"] = json!(format!("dns-{index}"));
                    rows.push(row);
                }
                let cfg = &mut rows[index]["config"];
                cfg["client_iface"] = json!(format!("awg{index}"));
                cfg["endpoint"] = json!(format!("198.51.100.{}:443", 10 + index));
                cfg["mtu"] = json!(1420);
                cfg["peers"] = json!([{
                    "id":"router","is_router":true,"address":addresses,"allowed_ips":grants
                }]);
                cfg["routing"]["zones"] = json!([{
                    "enabled":true,"domains":[name],"include_subdomains":false
                }]);
            }
            Ok(())
        })
        .unwrap();
        let sample = |cfg: &Value, iface: &str| {
            let mut live = peer(cfg, "awg0")?;
            live.endpoint = cfg["endpoint"].as_str().unwrap().parse().unwrap();
            live.allowed = match iface {
                "awg0" => vec!["0.0.0.0/0".into()],
                "awg1" => vec!["0.0.0.0/0".into(), "::/0".into()],
                "awg2" => vec!["::/0".into()],
                _ => panic!("unexpected target {iface}"),
            };
            Ok(live)
        };
        let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
        assert_eq!(request.names, [DUAL_NAME, V4_NAME, V6_NAME]);
        assert_eq!(request.dual_stack, [DUAL_NAME]);
        assert_eq!(request.ipv6_only, [V6_NAME]);
        let mut dual = vec![DUAL_V4_HOST.parse().unwrap()];
        if complete {
            dual.extend(
                DUAL_V6_HOSTS
                    .into_iter()
                    .rev()
                    .map(|ip| ip.parse::<std::net::IpAddr>().unwrap()),
            );
        }
        let mut snapshot = DnsSnapshot {
            request,
            answers: [
                (
                    V4_NAME.into(),
                    V4_HOSTS
                        .into_iter()
                        .rev()
                        .map(|ip| ip.parse().unwrap())
                        .collect(),
                ),
                (DUAL_NAME.into(), dual),
                (
                    V6_NAME.into(),
                    V6_HOSTS
                        .into_iter()
                        .rev()
                        .map(|ip| ip.parse().unwrap())
                        .collect(),
                ),
            ]
            .into(),
        };
        let now = nfqws2_awg_profile::now();
        operate_with_dns_at(&db, &router, Operation::Apply, now, Some(&snapshot), sample).unwrap();
        operate_at(&db, &router, Operation::Commit, now, sample).unwrap();
        let ticket = confirmed_static_dns_retry(&db, &snapshot.request).unwrap();
        assert_eq!(forward(&router.v4, LAN, DUAL_V4_HOST), "awg1");
        for ip in V4_HOSTS {
            assert_eq!(forward(&router.v4, LAN, ip), "awg0");
        }
        for ip in DUAL_V6_HOSTS {
            assert_eq!(
                forward(&router.v6, "fd70::42", ip),
                if complete { "awg1" } else { "wan0" }
            );
        }
        for ip in V6_HOSTS {
            assert_eq!(forward(&router.v6, "fd70::42", ip), "awg2");
        }
        if !complete {
            // An absent AAAA can still be part of the ordinary live apply.
            assert!(ticket.is_none());
            continue;
        }
        let ticket = ticket.unwrap();
        for addresses in snapshot.answers.values_mut() {
            addresses.sort_unstable();
        }
        assert_eq!(ticket.snapshot(), &snapshot);
        let baseline = Journal::read(&db).unwrap();
        let writes = |router: &Dual| {
            (
                router.v4.0.lock().unwrap().changes,
                router.v6.0.lock().unwrap().changes,
            )
        };
        let before_writes = writes(&router);
        let set_mtu = |mtu| {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["servers"][1]["config"]["mtu"] = json!(mtu);
                Ok(())
            })
            .unwrap();
        };
        set_mtu(1380);
        assert!(confirmed_static_dns_retry(&db, &snapshot.request)
            .unwrap()
            .is_none());
        assert!(apply_confirmed_static_dns_retry(
            &db,
            &router,
            &ticket,
            |_, _| { panic!("a different target MTU invalidates the exact retry") },
            || Ok(())
        )
        .is_err());
        assert_eq!(Journal::read(&db).unwrap(), baseline);
        assert_eq!(writes(&router), before_writes);
        set_mtu(1420);
        apply_confirmed_static_dns_retry(&db, &router, &ticket, sample, || Ok(())).unwrap();
        operate_at(&db, &router, Operation::Commit, now, sample).unwrap();
        assert_eq!(Journal::read(&db).unwrap(), baseline);
        assert_eq!(writes(&router), before_writes);
    }
}

#[test]
fn saved_sni_flag_keeps_exact_resolution_and_numeric_go_entries_out_of_dns() {
    let (_dir, db, f) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing"]["sni_routing"] = json!(true);
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"enabled":true,"domains":["office.example.test","203.0.113.32/28"],"include_subdomains":false}
        ]);
        Ok(())
    }).unwrap();
    let request = dns_request(&db, Operation::Apply).unwrap().unwrap();
    assert_eq!(request.names, ["office.example.test"]);
    let snapshot = DnsSnapshot {
        request,
        answers: BTreeMap::from([("office.example.test".to_owned(), vec![OLD.parse().unwrap()])]),
    };
    let now = nfqws2_awg_profile::now();
    operate_with_dns_at(&db, &f, Operation::Apply, now, Some(&snapshot), peer).unwrap();
    action(&db, &f, Operation::Commit, now + 1).unwrap();
    assert_eq!(path(&f, OLD), "awg0");
    assert_eq!(path(&f, "203.0.113.35"), "awg0");
    assert_eq!(path(&f, "203.0.113.48"), "wan0");
}

#[test]
fn pre_ipv6_trial_commits_and_refreshes_its_original_ipv4_request() {
    let (_temp, db, f) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"enabled":true,"route":"direct","domains":["skip.example.test"],"include_subdomains":false},
            {"enabled":true,"route":"tunnel","domains":["office.example.test"],"include_subdomains":false}
        ]);
        Ok(())
    }).unwrap();
    let dns = snapshot(&db, Operation::Apply, OLD);
    assert_eq!(dns.request.dual_stack, ["skip.example.test"]);
    let mut legacy = dns.clone();
    legacy.request.dual_stack.clear();
    assert!(operate_dns(&db, &f, Operation::Apply, Some(&legacy), [true; 2]).is_err());
    operate_dns(&db, &f, Operation::Apply, Some(&dns), [true; 2]).unwrap();
    let mut receipt = Journal::read(&db).unwrap();
    receipt.installed.dns.as_mut().unwrap().snapshot.request = legacy.request.clone();
    db.transaction(|tx| tx.save_runtime(RECEIPT, &receipt))
        .unwrap();
    operate_dns(&db, &f, Operation::Commit, None, [true; 2]).unwrap();
    let refreshed = snapshot(&db, Operation::Refresh, NEW);
    assert_eq!(refreshed.request, legacy.request);
    operate_dns(&db, &f, Operation::Refresh, Some(&refreshed), [true; 2]).unwrap();
    assert_eq!(forward(&f, LAN, NEW), "awg0");
}

#[test]
fn expiring_trial_recovers_original_dns_generation_without_a_second_lookup() {
    let (_temp, db, f) = fixture(true);
    confirm(&db, &f);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing_revision"] = json!(2);
        doc["servers"][0]["config"]["routing"]["zones"][1]["ips"] = json!(["203.0.113.201"]);
        Ok(())
    })
    .unwrap();
    let trial = snapshot(&db, Operation::Apply, NEW);
    operate_with_dns_at(&db, &f, Operation::Apply, 200, Some(&trial), both_peers).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::Expires(290));
    assert!(dns_request(&db, Operation::Refresh).unwrap().is_none());
    operate_with_dns_at(&db, &f, Operation::Refresh, 201, None, both_peers).unwrap();
    assert_eq!(forward(&f, LAN, NEW), "awg0");
    assert_eq!(forward(&f, LAN, OLD), "wan0");
    assert!(operate_with_dns_at(&db, &f, Operation::Commit, 291, None, both_peers).is_err());
    operate_with_dns_at(&db, &f, Operation::Recover, 291, None, both_peers).unwrap();
    assert_eq!(forward(&f, LAN, OLD), "awg0");
    assert_eq!(forward(&f, LAN, COMMON), "awg0");
    assert_eq!(forward(&f, LAN, NEW), "wan0");
    assert!(dns_request(&db, Operation::Refresh).unwrap().is_none());
}

#[test]
fn a_shadowed_dns_zone_cannot_acquire_a_replaced_peer_identity_on_rotation() {
    let (_temp, db, f) = setup();
    nfqws2_awg_profile::edit_document(&db,|doc| {
        doc["servers"][0]["config"]["routing"]["zones"] = json!([
            {"enabled":true,"route":"direct","domains":["skip.example.test"],"include_subdomains":false},
            {"enabled":true,"route":"tunnel","domains":["office.example.test"],"include_subdomains":false}
        ]);
        Ok(())
    }).unwrap();
    let dns = snapshot(&db, Operation::Apply, "203.0.113.9");
    operate_dns(&db, &f, Operation::Apply, Some(&dns), [true; 2]).unwrap();
    operate_dns(&db, &f, Operation::Commit, None, [true; 2]).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::Dns);
    assert_eq!(f.0.lock().unwrap().changes, 0);
    let fresh = snapshot(&db, Operation::Refresh, NEW);
    let key = |k: &str| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][0]["config"]["public_key"] = json!(k);
            Ok(())
        })
        .unwrap()
    };
    key("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
    assert!(
        operate_with_dns(&db, &f, Operation::Refresh, Some(&fresh), |_, _| panic!(
            "unapproved identity"
        ))
        .is_err()
    );
    assert_eq!(f.0.lock().unwrap().changes, 0);
    key(KEY);
    operate_dns(&db, &f, Operation::Refresh, Some(&fresh), [true; 2]).unwrap();
    assert_eq!(forward(&f, LAN, NEW), "awg0");
    assert_eq!(forward(&f, LAN, "203.0.113.9"), "wan0");
}

#[test]
fn ordered_names_static_cidrs_and_scoped_exceptions_survive_rotation_and_reboot() {
    let (_temp, db, f) = fixture(true);
    confirm(&db, &f);
    assert_eq!(forward(&f, LAN, OLD), "awg0");
    assert_eq!(forward(&f, LAN, "203.0.113.9"), "wan0");
    assert_eq!(forward(&f, "192.168.1.19", "203.0.113.9"), "awg0");
    assert_eq!(forward(&f, "192.168.2.19", OLD), "wan0");
    f.0.lock().unwrap().watch_flow = Some((LAN, COMMON));
    let fresh = snapshot(&db, Operation::Refresh, NEW);
    operate_dns(&db, &f, Operation::Refresh, Some(&fresh), [false, true]).unwrap();
    assert_eq!(forward(&f, LAN, OLD), "wan0");
    assert_eq!(forward(&f, LAN, NEW), "awg1");
    assert_eq!(forward(&f, LAN, COMMON), "awg1");
    assert!(!f.0.lock().unwrap().leaked);
    f.0.lock().unwrap().watch_flow = None;
    operate_dns(&db, &f, Operation::Suspend, None, [false; 2]).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    *f.0.lock().unwrap() = Firmware {
        boot: "10101010-1010-1010-1010-101010101010".into(),
        local: "2: br0 inet 192.168.1.1/24 scope global".into(),
        ..Default::default()
    };
    assert!(dns_request(&db, Operation::Recover).unwrap().is_none());
    operate_dns(&db, &f, Operation::Recover, None, [false; 2]).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::Dns);
    assert_eq!(forward(&f, LAN, NEW), "blackhole");
    assert_eq!(forward(&f, LAN, OLD), "wan0");
    assert_eq!(forward(&f, LAN, "203.0.113.9"), "wan0");
    operate_dns(&db, &f, Operation::Refresh, None, [false, true]).unwrap();
    assert_eq!(forward(&f, LAN, NEW), "awg1");
}

#[test]
fn refresh_rejects_stale_revision_and_failed_dns_still_recovers_committed_peer() {
    let (_temp, db, f) = fixture(true);
    confirm(&db, &f);
    let fresh = snapshot(&db, Operation::Refresh, NEW);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["routing_revision"] = json!(2);
        doc["servers"][0]["config"]["routing"]["zones"][1]["domains"] =
            json!(["draft.example.test"]);
        Ok(())
    })
    .unwrap();
    assert!(dns_request(&db, Operation::Refresh).unwrap().is_none());
    let before = f.0.lock().unwrap().changes;
    assert!(operate_dns(&db, &f, Operation::Refresh, Some(&fresh), [true; 2]).is_err());
    assert!(operate_dns(&db, &f, Operation::Apply, Some(&fresh), [true; 2]).is_err());
    assert_eq!(f.0.lock().unwrap().changes, before);
    operate_dns(&db, &f, Operation::Refresh, None, [false, true]).unwrap();
    assert_eq!(forward(&f, LAN, OLD), "awg1");
    assert_eq!(forward(&f, LAN, NEW), "wan0");
    operate_dns(&db, &f, Operation::Refresh, None, [false; 2]).unwrap();
    assert_eq!(forward(&f, LAN, OLD), "blackhole");
}

#[test]
fn unsafe_incomplete_or_unroutable_rotation_preserves_committed_fib() {
    for kill in [false, true] {
        let (_temp, db, f) = fixture(kill);
        confirm(&db, &f);
        let original = Journal::read(&db).unwrap();
        let before = f.0.lock().unwrap().changes;
        for addr in [
            "198.51.100.10",
            "192.168.1.111",
            "127.0.0.1",
            "169.254.0.5",
            "224.0.0.1",
        ] {
            let dns = snapshot(&db, Operation::Refresh, addr);
            assert!(operate_dns(&db, &f, Operation::Refresh, Some(&dns), [true; 2]).is_err());
        }
        let mut direct = snapshot(&db, Operation::Refresh, NEW);
        direct.answers.insert(
            "skip.example.test".into(),
            vec!["198.51.100.10".parse().unwrap()],
        );
        assert!(operate_dns(&db, &f, Operation::Refresh, Some(&direct), [true; 2]).is_err());
        let mut partial = snapshot(&db, Operation::Refresh, NEW);
        partial.answers.remove("skip.example.test");
        assert!(operate_dns(&db, &f, Operation::Refresh, Some(&partial), [true; 2]).is_err());
        let valid = snapshot(&db, Operation::Refresh, NEW);
        assert!(operate_dns(&db, &f, Operation::Refresh, Some(&valid), [false; 2]).is_err());
        assert!(
            operate_with_dns(&db, &f, Operation::Refresh, Some(&valid), |c, i| {
                let mut peer = both_peers(c, i)?;
                peer.allowed = vec!["203.0.113.8/31".into()];
                Ok(peer)
            })
            .is_err()
        );
        assert_eq!(f.0.lock().unwrap().changes, before);
        assert!(Journal::read(&db).unwrap() == original);
        assert_eq!(forward(&f, LAN, OLD), "awg0");
        assert_eq!(forward(&f, LAN, NEW), "wan0");
        if kill {
            f.0.lock().unwrap().watch_flow = Some((LAN, COMMON));
        }
        f.0.lock().unwrap().fail_selector_once = true;
        assert!(operate_dns(&db, &f, Operation::Refresh, Some(&valid), [true; 2]).is_err());
        assert!(Journal::read(&db).unwrap() == original);
        assert_eq!(forward(&f, LAN, OLD), "awg0");
        assert_eq!(forward(&f, LAN, NEW), "wan0");
        assert!(!f.0.lock().unwrap().leaked);
    }
}

#[test]
fn names_must_be_exact_and_snapshots_are_bounded_and_complete() {
    let (_temp, db, f) = fixture(false);
    let query = snapshot(&db, Operation::Apply, OLD);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        for zone in doc["servers"][0]["config"]["routing"]["zones"]
            .as_array_mut()
            .unwrap()
        {
            zone["source_ips"] = json!([]);
        }
        Ok(())
    })
    .unwrap();
    for (key, value) in [
        ("domains", json!(["127.1"])),
        ("domains", json!(["0x7f000001"])),
        ("domains", json!(["a.test.."])),
        (
            "domains",
            json!((0..33).map(|n| format!("name{n}.test")).collect::<Vec<_>>()),
        ),
    ] {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            let z = &mut doc["servers"][0]["config"]["routing"]["zones"][1];
            z["include_subdomains"] = json!(false);
            z["domains"] = json!(["office.example.test"]);
            z[key] = value;
            Ok(())
        })
        .unwrap();
        assert!(
            dns_request(&db, Operation::Apply).is_err(),
            "{key} should reject invalid eager DNS input"
        );
    }
    let mut extra = query.clone();
    extra.answers.insert(
        "unused.example.test".into(),
        vec![Ipv4Addr::new(203, 0, 113, 1).into()],
    );
    assert!(extra.validate(query.request.revision).is_err());
    let mut many = query.clone();
    many.answers.insert(
        "skip.example.test".into(),
        (1..=17)
            .map(|n| Ipv4Addr::new(203, 0, 113, n).into())
            .collect(),
    );
    assert!(many.validate(query.request.revision).is_err());
    let mut none = query;
    none.answers.values_mut().next().unwrap().clear();
    assert!(none.validate(none.request.revision).is_err());
    assert_eq!(f.0.lock().unwrap().changes, 0);
}
