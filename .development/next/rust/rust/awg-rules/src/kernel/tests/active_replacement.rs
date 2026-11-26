use super::*;
use nfqws2_awg_profile::{
    active_replacement_fingerprint, active_replacement_nested_mtu,
    active_replacement_underlay_identity, ActiveReplacementPeer, ActiveReplacementStage,
    ActiveReplacementUnderlay, NativeNestedRemovalScope, NativeRemovalSeal,
    ACTIVE_REPLACEMENT_FIELD,
};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const LEASE: &str = "awg-active-replacement.json";
const REBOOT: &str = "34343434-3434-3434-3434-343434343434";
const SOURCE: &str = "active-source";
const TARGET: &str = "running-target";
const OUTER: &str = "kept-optional-outer";
const TARGET_OUTER: &str = "independent-target-outer";
const CLIENT: &str = "192.168.1.42";
const DEST: &str = "203.0.113.9";
const SECOND_DEST: &str = "198.18.24.9";

fn fixture(killswitch: bool) -> (tempfile::TempDir, Store, Fake) {
    fixture_with_zones(
        killswitch,
        json!([{ "name":"protected", "enabled":true, "ips":["203.0.113.0/24"] }]),
        ["", ""],
    )
}

fn multi_prefix_fixture(killswitch: bool, separate: bool) -> (tempfile::TempDir, Store, Fake) {
    let zones = if separate {
        json!([
            {"name":"first","order":1,"enabled":true,"ips":["203.0.113.0/24"]},
            {"name":"second","order":2,"enabled":true,"ips":["198.18.24.0/24"]}
        ])
    } else {
        json!([
            {"name":"both","order":1,"enabled":true,"ips":["203.0.113.0/24","198.18.24.0/24"]}
        ])
    };
    let target = if separate { "last_resort" } else { "preferred" };
    fixture_with_zones(killswitch, zones, ["automatic", target])
}

fn optional_outer_fixture(killswitch: bool, modes: [&str; 2]) -> (tempfile::TempDir, Store, Fake) {
    let (temp, db, fw) = multi_prefix_fixture(killswitch, true);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let mut outer = rows[1].clone();
        outer["id"] = json!(OUTER);
        outer["config"]["client_iface"] = json!("awg2");
        outer["config"]["endpoint"] = json!("198.51.100.12:443");
        outer["config"]["client"]["double_tunnel_mode"] = json!("off");
        for (row, mode) in rows.iter_mut().zip(modes) {
            row["config"]["client"]["double_tunnel_mode"] = json!(mode);
            row["config"]["client"]["double_tunnel_id"] = json!(OUTER);
        }
        rows.push(outer);
        Ok(())
    })
    .unwrap();
    (temp, db, fw)
}

fn fixture_with_zones(
    killswitch: bool,
    zones: Value,
    modes: [&str; 2],
) -> (tempfile::TempDir, Store, Fake) {
    let (tmp, db, f) = profile_fixture(killswitch, zones, modes);
    let now = nfqws2_awg_profile::now();
    action(&db, &f, Operation::Apply, now).unwrap();
    action(&db, &f, Operation::Commit, now).unwrap();
    f.0.lock().unwrap().watch_flow = Some((CLIENT, DEST));
    (tmp, db, f)
}

fn profile_fixture(
    killswitch: bool,
    zones: Value,
    modes: [&str; 2],
) -> (tempfile::TempDir, Store, Fake) {
    let (tmp, db, f) = setup();
    for (local, endpoint) in [
        ("192.0.2.20", "198.51.100.10"),
        ("192.0.2.21", "198.51.100.11"),
    ] {
        nfqws2_awg_profile::import(&db, &format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = {local}/32\n\n[Peer]\nPublicKey = {KEY}\nEndpoint = {endpoint}:443\nAllowedIPs = 0.0.0.0/0\n"
        ), "fixture").unwrap();
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        rows.remove(0);
        for (index, id) in [SOURCE, TARGET].iter().enumerate() {
            let row = &mut rows[index];
            row["id"] = json!(id);
            row["config"]["client_iface"] = json!(format!("awg{index}"));
            row["config"]["client"]["enabled"] = json!(true);
            row["config"]["client"]["rust_managed"] = json!(true);
            row["config"]["client"]["standby"] = json!(index == 1);
            row["config"]["client"]["double_tunnel_mode"] = json!(modes[index]);
            row["config"]["routing"] = json!({"mode":"zones","active":false,"zones":[]});
        }
        rows[0]["config"]["routing"]["zones"] = zones;
        doc["active_id"] = json!(SOURCE);
        doc["routing"] = json!({"mode":"zones","killswitch":killswitch});
        Ok(())
    })
    .unwrap();
    (tmp, db, f)
}

fn candidate(doc: &Value) -> Value {
    let mut next = doc.clone();
    let rows = next["servers"].as_array_mut().unwrap();
    let old = rows.remove(0);
    let mut zones = old["config"]["routing"]["zones"].clone();
    for (i, zone) in zones.as_array_mut().unwrap().iter_mut().enumerate() {
        zone["tunnel_id"] = json!(TARGET);
        zone["order"] = json!(i + 1);
    }
    rows[0]["config"]["routing"]["zones"] = zones;
    rows[0]["config"]["routing"]["active"] = json!(true);
    rows[0]["config"]["client"]["standby"] = json!(false);
    next["active_id"] = json!(TARGET);
    next["routing_revision"] = json!(2);
    next
}

fn peers(doc: &Value) -> [ActiveReplacementPeer; 2] {
    [SOURCE, TARGET].map(|id| {
        let is_target = id == TARGET;
        let index = u32::from(is_target);
        ActiveReplacementPeer {
            owner: NativeRemovalSeal {
                id: id.into(),
                iface: format!("awg{index}"),
                boot: BOOT.into(),
                pid: 200 + index,
                started: 500 + u64::from(index),
                receipt_sha256: [index as u8 + 1; 32],
                nested: None,
            },
            fingerprint: active_replacement_fingerprint(doc, id).unwrap(),
            endpoint: if is_target {
                "198.51.100.11:443"
            } else {
                "198.51.100.10:443"
            }
            .parse()
            .unwrap(),
            socket_mark: 0,
            mtu: 1420,
            allowed: vec!["0.0.0.0/0".into()],
            underlay: None,
            nested_only: false,
        }
    })
}

fn transfer(
    db: &Store,
    run: &dyn Runner,
    before: &Value,
    records: &[ActiveReplacementPeer; 2],
) -> io::Result<Option<String>> {
    let after = candidate(before);
    db.transaction(|tx| {
        replace_active_profile(db, tx, run, before, &after, records, &["wan0".into()])
    })
}

#[test]
fn active_named_replacement_requires_both_bound_wan_peers_and_every_dns_claim() {
    use nfqws2_awg_profile::active_named_replacement_fingerprint;
    use std::net::SocketAddr;
    let (_tmp, db, fw) = fixture(true);
    let mut records = peers(&nfqws2_awg_profile::read(&db).unwrap());
    let names = ["live-source.test:443", "live-target.test:443"];
    nfqws2_awg_profile::edit_document(&db, |doc| {
        for (row, name) in doc["servers"].as_array_mut().unwrap().iter_mut().zip(names) {
            row["config"]["endpoint"] = json!(name);
        }
        Ok(())
    })
    .unwrap();
    let before = nfqws2_awg_profile::read(&db).unwrap();
    for record in &mut records {
        record.fingerprint = active_named_replacement_fingerprint(&before, &record.owner.id).unwrap();
    }
    let make_proof = |extra: Option<SocketAddr>| {
        NamedActiveReplacement::prepare(&db, &before, SOURCE, TARGET, |_, id, _| {
            Ok(if id == SOURCE {
                vec![records[0].endpoint]
            } else {
                std::iter::once(records[1].endpoint).chain(extra).collect()
            })
        }).unwrap().unwrap()
    };
    let writes = std::cell::Cell::new(0);
    let after = candidate(&before);
    let attempt = |peers: &[ActiveReplacementPeer; 2], names: &NamedActiveReplacement| {
        db.transaction(|tx| replace_active_profile_with_names(
            &db, tx, &fw, &before, &after, (peers, &["wan0".into()], names),
            || { writes.set(writes.get() + 1); Ok(()) },
        ))
    };
    let mut wrong = records.clone();
    wrong[1].endpoint.set_port(444);
    assert!(attempt(&wrong, &make_proof(None)).is_err());
    wrong[1] = records[1].clone();
    wrong[1].socket_mark = 0x1000;
    assert!(attempt(&wrong, &make_proof(None)).is_err());
    wrong[1] = records[1].clone();
    wrong[1].fingerprint[0] ^= 1;
    assert!(attempt(&wrong, &make_proof(None)).is_err());
    assert!(attempt(&records, &make_proof(Some("203.0.113.99:443".parse().unwrap()))).is_err());
    assert_eq!(writes.get(), 0);
    assert!(!active_replacement_in_progress(&db).unwrap());
    assert_eq!(fw.0.lock().unwrap().forward(CLIENT, DEST), "awg0");
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);

    attempt(&records, &make_proof(Some("[2001:db8:11::20]:443".parse().unwrap()))).unwrap();
    assert_eq!(writes.get(), 1);
    assert_eq!(fw.0.lock().unwrap().forward(CLIENT, DEST), "awg1");
    let migrated = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(migrated["servers"][0]["config"]["endpoint"], names[1]);
    assert_eq!(pending_active_replacement_retirement(&db).unwrap(), Some(records[0].owner.clone()));
}

fn launch_preflight(
    db: &Store,
    run: &dyn Runner,
    before: &Value,
    source: &ActiveReplacementPeer,
    provisional: Option<&ActiveReplacementPeer>,
) -> io::Result<()> {
    prepare_active_replacement_launch(
        db,
        run,
        ActiveReplacementStage {
            before,
            after: &candidate(before),
            source,
            held: None,
            target: TARGET,
            provisional,
        },
        &["wan0".into()],
        None,
    )
    .map(|_| ())
}

#[test]
fn cold_replacement_preflight_is_read_only_and_replay_can_stop_only_the_sealed_unused_target() {
    let (_tmp, db, f) = fixture(true);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let [source, mut target] = peers(&before);
    let baseline = Journal::read(&db).unwrap();
    let changes = f.0.lock().unwrap().changes;
    launch_preflight(&db, &f, &before, &source, None).unwrap();
    assert!(!active_replacement_in_progress(&db).unwrap());
    let allowed = std::mem::replace(&mut target.allowed, vec!["203.0.113.9/32".into()]);
    assert!(launch_preflight(&db, &f, &before, &source, Some(&target)).is_err());
    assert!(!active_replacement_in_progress(&db).unwrap());
    target.allowed = allowed;
    launch_preflight(&db, &f, &before, &source, Some(&target)).unwrap();
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    assert!(action(&db, &f, Operation::Apply, nfqws2_awg_profile::now()).is_err());
    let cleanup = active_replacement_launch_cleanup(&db).unwrap().unwrap();
    assert_eq!(cleanup.target, target.owner);
    assert!(cleanup.stop);
    let mut stale = cleanup.target.clone();
    stale.started += 1;
    assert!(finish_active_replacement_launch_cleanup(
        &db,
        &ActiveReplacementLaunchCleanup {
            target: stale,
            stop: true
        }
    )
    .is_err());
    finish_active_replacement_launch_cleanup(&db, &cleanup).unwrap();
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg0");
    assert_eq!(Journal::read(&db).unwrap(), baseline);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
}

#[test]
fn cold_ordinary_launch_cleanup_refuses_a_changed_standby_setting() {
    let (_tmp, db, f) = fixture(true);
    let save_standby = |standby| {
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["servers"][1]["config"]["client"]["standby"] = json!(standby);
            Ok(())
        })
        .unwrap();
    };
    save_standby(false);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&before);
    launch_preflight(&db, &f, &before, &records[0], None).unwrap();
    launch_preflight(&db, &f, &before, &records[0], Some(&records[1])).unwrap();
    assert!(active_replacement_launch_cleanup(&db).unwrap().unwrap().stop);
    save_standby(true);
    assert!(active_replacement_launch_cleanup(&db).is_err());
    save_standby(false);
    let cleanup = active_replacement_launch_cleanup(&db).unwrap().unwrap();
    assert_eq!(cleanup.target, records[1].owner);
    finish_active_replacement_launch_cleanup(&db, &cleanup).unwrap();
    assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg0");
}

#[test]
fn cold_replacement_keeps_an_adopted_target_and_retires_the_original_source() {
    let (_tmp, db, f) = fixture(true);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let mut records = peers(&before);
    launch_preflight(&db, &f, &before, &records[0], None).unwrap();
    launch_preflight(&db, &f, &before, &records[0], Some(&records[1])).unwrap();
    let baseline = f.0.lock().unwrap().changes;
    records[1].owner.started += 1;
    assert!(transfer(&db, &f, &before, &records).is_err());
    assert_eq!(f.0.lock().unwrap().changes, baseline);
    records[1].owner.started -= 1;
    transfer(&db, &f, &before, &records).unwrap();
    let adopted = active_replacement_launch_cleanup(&db).unwrap().unwrap();
    assert!(!adopted.stop);
    assert_eq!(adopted.target, records[1].owner);
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());
    assert!(finish_active_replacement_retirement(&db, &records[0].owner).is_err());
    let mut wrong = adopted.target.clone();
    wrong.pid += 1;
    assert!(finish_active_replacement_launch_cleanup(
        &db,
        &ActiveReplacementLaunchCleanup {
            target: wrong,
            stop: false
        }
    )
    .is_err());
    finish_active_replacement_launch_cleanup(&db, &adopted).unwrap();
    let source = pending_active_replacement_retirement(&db).unwrap().unwrap();
    assert_eq!(source, records[0].owner);
    finish_active_replacement_retirement(&db, &source).unwrap();
    assert!(!active_replacement_in_progress(&db).unwrap());
    assert!(!f.0.lock().unwrap().leaked);
    assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg1");
}

#[test]
fn cold_replacement_recovers_the_source_before_retiring_a_provisional_peer() {
    let (_tmp, db, f) = fixture(true);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&before);
    launch_preflight(&db, &f, &before, &records[0], Some(&records[1])).unwrap();
    transfer(&db, &f, &before, &records).unwrap();
    let next = Journal::read(&db).unwrap();
    let mut interrupted = before.clone();
    stamp_document(&mut interrupted, &next).unwrap();
    db.transaction(|tx| tx.save("awg.json", &interrupted))
        .unwrap();
    assert!(active_replacement_launch_cleanup(&db).unwrap().is_none());
    action(&db, &f, Operation::Recover, nfqws2_awg_profile::now()).unwrap();
    assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg0");
    assert!(!f.0.lock().unwrap().leaked);
    let cleanup = active_replacement_launch_cleanup(&db).unwrap().unwrap();
    assert!(cleanup.stop && cleanup.target == records[1].owner);
    finish_active_replacement_launch_cleanup(&db, &cleanup).unwrap();
    assert!(!active_replacement_in_progress(&db).unwrap());
}

#[test]
fn active_replacement_keeps_the_original_stop_and_commits_the_retirement_lease() {
    let (_tmp, db, f) = fixture(true);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&before);
    let prior = Journal::read(&db).unwrap();
    assert_eq!(transfer(&db, &f, &before, &records).unwrap(), None);
    {
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.forward(CLIENT, DEST), "awg1");
        assert!(!fw.leaked);
    }
    let now = Journal::read(&db).unwrap();
    assert_eq!(now.committed.revision, 2);
    let stops = |p: &Plan| {
        objects(p)
            .into_iter()
            .filter(|x| x.is_stop())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(stops(&prior.installed), stops(&now.installed));
    assert_eq!(stops(&now.installed).len(), 1);
    let after = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(after["active_id"], TARGET);
    assert_eq!(after["servers"].as_array().unwrap().len(), 1);
    assert_eq!(after["servers"][0]["config"]["client"]["standby"], false);
    let mut wrong = records[0].owner.clone();
    wrong.started += 1;
    assert!(finish_active_replacement_retirement(&db, &wrong).is_err());
    let seal = pending_active_replacement_retirement(&db).unwrap().unwrap();
    assert_eq!(seal, records[0].owner);
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    finish_active_replacement_retirement(&db, &seal).unwrap();
    finish_active_replacement_retirement(&db, &seal).unwrap();
    assert!(!active_replacement_in_progress(&db).unwrap());
    assert!(nfqws2_awg_profile::read(&db)
        .unwrap()
        .get(ACTIVE_REPLACEMENT_FIELD)
        .is_none());
    let status = inspect(&db, &f).unwrap();
    assert!(status.active && status.ready && !status.pending_commit);
}

#[test]
fn active_replacement_preserves_source_membership_and_rejects_scope_changes() {
    const OUTSIDE: &str = "192.168.1.82";
    const SECOND_CLIENT: &str = "192.168.1.153";
    for killswitch in [true, false] {
        let (_tmp, db, f) = profile_fixture(
            killswitch,
            json!([
                {"name":"first", "enabled":true, "order":1, "ips":["203.0.113.0/24"], "source_ips":["192.168.1.32/27"]},
                {"name":"second", "enabled":true, "order":2, "ips":["203.0.113.0/24"], "source_ips":["192.168.1.128/26"]}
            ]),
            ["automatic", "last_resort"],
        );
        f.0.lock().unwrap().local = "3: br0 inet 192.168.1.1/24".into();
        let now = nfqws2_awg_profile::now();
        action(&db, &f, Operation::Apply, now).unwrap();
        action(&db, &f, Operation::Commit, now).unwrap();
        let prior = Journal::read(&db).unwrap();
        assert_eq!(prior.installed.scoped.len(), 2);
        f.0.lock().unwrap().watch_flow = Some((CLIENT, DEST));
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let records = peers(&before);
        let changes = f.0.lock().unwrap().changes;
        assert_eq!(f.0.lock().unwrap().forward(OUTSIDE, DEST), "wan0");
        let mut rejected = candidate(&before);
        rejected["servers"][0]["config"]["routing"]["zones"][0]["source_ips"] =
            json!(["192.168.1.64/26"]);
        assert!(db
            .transaction(|tx| {
                replace_active_profile(&db, tx, &f, &before, &rejected, &records, &["wan0".into()])
            })
            .is_err());
        let mut partial = records.clone();
        partial[1].allowed = vec!["203.0.113.0/25".into()];
        assert!(transfer(&db, &f, &before, &partial).is_err());
        assert_eq!(f.0.lock().unwrap().changes, changes);
        assert_eq!(Journal::read(&db).unwrap(), prior);
        transfer(&db, &f, &before, &records).unwrap();
        let current = Journal::read(&db).unwrap();
        assert_eq!(current.installed.killswitch, killswitch);
        assert!(prior
            .installed
            .flows()
            .map(|(s, _)| s)
            .eq(current.installed.flows().map(|(s, _)| s)));
        let firewall = f.0.lock().unwrap();
        assert_eq!(firewall.forward(CLIENT, DEST), "awg1");
        assert_eq!(firewall.forward(SECOND_CLIENT, DEST), "awg1");
        assert_eq!(firewall.forward(OUTSIDE, DEST), "wan0");
        assert!(!firewall.leaked);
    }
}

#[test]
fn active_replacement_rebinds_empty_dns_learner_without_transferring_old_confirmations() {
    const DOMAIN: &str = "media.corp.example";
    const HOST: &str = "198.18.5.33";
    for killswitch in [true, false] {
        let (_tmp, db, f) = profile_fixture(
            killswitch,
            json!([{"name":"media", "enabled":true, "order":1, "ips":["203.0.113.0/24"], "domains":["*.corp.example"]}]),
            ["automatic", "last_resort"],
        );
        nfqws2_awg_profile::edit_document(&db, |doc| {
            doc["routing"]["domain_source"] = json!("dnsproxy");
            Ok(())
        })
        .unwrap();
        for op in [Operation::Apply, Operation::Commit] {
            operate_with_redirect(&db, &f, op, None, None, peer).unwrap();
        }
        let prior = Journal::read(&db).unwrap();
        assert_eq!(
            active_replacement_dns_redirects(&db, SOURCE).unwrap(),
            Some((1, Vec::new()))
        );
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let records = peers(&before);
        let mut rejected = candidate(&before);
        rejected["servers"][0]["config"]["routing"]["zones"][0]["domains"] =
            json!(["different.example"]);
        let opened = std::cell::Cell::new(false);
        let checked_transfer = |after: &Value| {
            db.transaction(|tx| {
                replace_active_profile_checked(
                    &db,
                    tx,
                    &f,
                    &before,
                    after,
                    (&records, &["wan0".into()]),
                    || {
                        opened.set(true);
                        Ok(())
                    },
                )
            })
        };
        assert!(checked_transfer(&rejected).is_err());
        assert!(!opened.get());
        assert_eq!(Journal::read(&db).unwrap(), prior);
        checked_transfer(&candidate(&before)).unwrap();
        assert!(opened.get());
        let next = Journal::read(&db).unwrap();
        assert!(next.installed.dns_bridges.is_empty());
        let live = |cfg: &Value, iface: &str| {
            assert_eq!(iface, "awg1");
            let mut live = peer(cfg, "awg0")?;
            live.endpoint = records[1].endpoint;
            Ok(live)
        };
        let replay = |revision| {
            learn_archived_answer(
                &db,
                &f,
                ArchiveAnswer {
                    revision,
                    name: DOMAIN,
                    addresses: &[HOST.parse().unwrap()],
                    ttl: 60,
                    qtype: 1,
                },
                live,
                || Ok(()),
            )
        };
        let published = observation(&db).unwrap().unwrap();
        assert!(published.ready);
        assert_eq!(published.revision, 2);
        assert_eq!(published.policy.matched(DOMAIN, None), Some(0));
        assert!(replay(1).is_err());
        assert!(next.installed.learned.as_ref().unwrap().members.is_empty());
        assert_eq!(f.0.lock().unwrap().forward(CLIENT, HOST), "wan0");
        finish_active_replacement_retirement(&db, &records[0].owner).unwrap();
        replay(2).unwrap();
        assert_eq!(f.0.lock().unwrap().forward(CLIENT, HOST), "awg1");
        assert!(active_replacement_dns_redirects(&db, TARGET).is_err());
    }
}

#[test]
fn active_replacement_has_no_wan_gap_after_each_failed_fib_write() {
    let writes = {
        let (_tmp, db, f) = fixture(true);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let old = f.0.lock().unwrap().changes;
        transfer(&db, &f, &before, &peers(&before)).unwrap();
        let writes = f.0.lock().unwrap().changes - old;
        writes
    };
    assert!(writes > 1);
    for failure in 1..=writes {
        let (_tmp, db, f) = fixture(true);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        {
            let mut fw = f.0.lock().unwrap();
            fw.fail_after = Some(fw.changes + failure);
        }
        assert!(
            transfer(&db, &f, &before, &peers(&before)).is_err(),
            "failure {failure}"
        );
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(doc["servers"][0]["id"], SOURCE);
        assert_eq!(doc["routing_revision"], 1);
        assert!(pending_active_replacement_retirement(&db)
            .unwrap()
            .is_none());
        assert!(!f.0.lock().unwrap().leaked, "failure {failure}");
        action(&db, &f, Operation::Recover, nfqws2_awg_profile::now()).unwrap();
        assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg0");
        assert!(!active_replacement_in_progress(&db).unwrap());
    }
}

#[test]
fn active_replacement_recovers_uncommitted_fib_and_a_cold_boot_without_retiring_source() {
    for (cold, preparing, later_draft) in [
        (false, false, false),
        (false, true, true),
        (true, false, false),
    ] {
        let (_tmp, db, f) = fixture(true);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let prior = Journal::read(&db).unwrap();
        transfer(&db, &f, &before, &peers(&before)).unwrap();
        let next = Journal::read(&db).unwrap();
        // The route writer finished, but the configuration deletion did not.
        let mut intermediate = before.clone();
        stamp_document(&mut intermediate, &next).unwrap();
        db.transaction(|tx| {
            if preparing {
                let mut phase = prior;
                phase.preparing.push(next.installed.clone());
                tx.save_runtime_bounded(RECEIPT, &phase, RECEIPT_LIMIT)?;
            }
            tx.save("awg.json", &intermediate)
        })
        .unwrap();
        if later_draft {
            edit_net(&db, "192.0.2.99/32");
        }
        assert!(db.read_runtime::<Value>(LEASE, 64 << 10).is_ok());
        assert!(pending_active_replacement_retirement(&db)
            .unwrap()
            .is_none());
        if cold {
            *f.0.lock().unwrap() = Firmware {
                boot: "34343434-3434-3434-3434-343434343434".into(),
                ..Firmware::default()
            };
        }
        action(&db, &f, Operation::Recover, nfqws2_awg_profile::now()).unwrap();
        assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg0");
        assert!(!f.0.lock().unwrap().leaked);
        assert!(!active_replacement_in_progress(&db).unwrap());
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(doc["active_id"], SOURCE);
        assert_eq!(doc["routing_revision"], if later_draft { 2 } else { 1 });
        assert_eq!(inspect(&db, &f).unwrap().ready, !later_draft);
        if later_draft {
            assert_eq!(
                doc["servers"][0]["config"]["routing"]["zones"][0]["ips"],
                json!(["192.0.2.99/32"])
            );
        }
    }
}

#[test]
fn active_replacement_rejects_an_unrelated_live_grant() {
    for killswitch in [false, true] {
        let (_tmp, db, f) = fixture(killswitch);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let mut records = peers(&before);
        records[1].allowed = vec!["203.0.113.9/32".into()];
        let changes = f.0.lock().unwrap().changes;
        assert!(transfer(&db, &f, &before, &records).is_err());
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert!(!active_replacement_in_progress(&db).unwrap());
        assert_eq!(f.0.lock().unwrap().changes, changes);
    }
}

struct StopWriter<'a> {
    inner: &'a Fake,
    added: AtomicU32,
    removed: AtomicU32,
    fail_release: AtomicBool,
}

impl<'a> StopWriter<'a> {
    fn new(inner: &'a Fake, fail_release: bool) -> Self {
        Self {
            inner,
            added: AtomicU32::new(0),
            removed: AtomicU32::new(0),
            fail_release: AtomicBool::new(fail_release),
        }
    }

    fn stop_writes(&self) -> (u32, u32) {
        (
            self.added.load(Ordering::Relaxed),
            self.removed.load(Ordering::Relaxed),
        )
    }
}

impl Runner for StopWriter<'_> {
    fn run(&self, prog: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        let result = self.inner.run(prog, args, deadline)?;
        match (prog, args) {
            ("ip", ["-4", "rule", "add", "pref", "69", ..]) => {
                self.added.fetch_add(1, Ordering::Relaxed);
            }
            ("ip", ["-4", "rule", "del", "pref", "69", ..]) => {
                self.removed.fetch_add(1, Ordering::Relaxed);
                if self.fail_release.swap(false, Ordering::Relaxed) {
                    return Err(io::Error::other(
                        "kernel accepted the guard removal before reporting failure",
                    ));
                }
            }
            _ => (),
        }
        Ok(result)
    }
}

fn replacement_peer(_: &Value, iface: &str) -> io::Result<LivePeer> {
    let endpoint = match iface {
        "awg0" => "198.51.100.10:443",
        "awg1" => "198.51.100.11:443",
        _ => panic!("unexpected replacement interface"),
    };
    LivePeer::from_uapi(
        std::path::Path::new("/"),
        iface,
        endpoint.parse().unwrap(),
        vec!["0.0.0.0/0".into()],
        0,
        false,
    )
}

#[test]
fn temporary_stop_is_installed_and_released_without_changing_disabled_kill_switch() {
    for from_standby in [false, true] {
        let (_tmp, db, f) = fixture(false);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let records = peers(&before);
        let runner = StopWriter::new(&f, false);
        if from_standby {
            launch_preflight(&db, &runner, &before, &records[0], None).unwrap();
            launch_preflight(&db, &runner, &before, &records[0], Some(&records[1])).unwrap();
            assert_eq!(runner.stop_writes(), (0, 0));
        }
        assert_eq!(transfer(&db, &runner, &before, &records).unwrap(), None);
        assert_eq!(runner.stop_writes(), (1, 1));
        let saved: Value = db.read_runtime(LEASE, 64 << 10).unwrap();
        assert!(saved["temporary_stop"].get("transport_policy").is_none());
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(doc["routing"]["killswitch"], false);
        assert_eq!(doc["active_id"], TARGET);
        let journal = Journal::read(&db).unwrap();
        assert_eq!(journal.installed, journal.committed);
        assert!(!journal.installed.killswitch);
        let fw = f.0.lock().unwrap();
        assert!(fw.stops.is_empty() && !fw.leaked);
        assert_eq!(fw.forward(CLIENT, DEST), "awg1");
        if from_standby {
            let cleanup = active_replacement_launch_cleanup(&db).unwrap().unwrap();
            assert!(!cleanup.stop);
            finish_active_replacement_launch_cleanup(&db, &cleanup).unwrap();
        }
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().as_ref(),
            Some(&records[0].owner)
        );
    }
}

#[test]
fn temporary_stop_recovers_every_failed_write_without_direct_fallback() {
    let writes = {
        let (_tmp, db, f) = fixture(false);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let baseline = f.0.lock().unwrap().changes;
        transfer(&db, &f, &before, &peers(&before)).unwrap();
        let count = f.0.lock().unwrap().changes - baseline;
        count
    };
    for index in 1..=writes {
        let (_tmp, db, f) = fixture(false);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        {
            let mut fw = f.0.lock().unwrap();
            fw.fail_after = Some(fw.changes + index);
        }
        let result = transfer(&db, &f, &before, &peers(&before));
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let (config_id, tunnel) = if let Ok(warning) = result {
            assert!(warning.is_some(), "write {index}");
            (TARGET, "awg1")
        } else {
            let old = f.0.lock().unwrap();
            assert_eq!(old.forward(CLIENT, DEST), "awg0", "write {index}");
            assert!(old.stops.is_empty(), "write {index}");
            (SOURCE, "awg0")
        };
        assert_eq!(doc["active_id"], config_id, "write {index}");
        assert_eq!(doc["routing"]["killswitch"], false);
        assert!(!f.0.lock().unwrap().leaked, "write {index}");
        operate_at(
            &db,
            &f,
            Operation::Recover,
            nfqws2_awg_profile::now(),
            replacement_peer,
        )
        .unwrap();
        let fw = f.0.lock().unwrap();
        assert!(!fw.leaked, "recovery for write {index}");
        assert!(fw.stops.is_empty(), "write {index}");
        assert_eq!(fw.forward(CLIENT, DEST), tunnel, "write {index}");
    }
}

#[test]
fn temporary_stop_preserves_unavailable_successor_until_recovery_or_explicit_teardown() {
    for (cold, teardown) in [(false, false), (true, false), (false, true)] {
        let (_tmp, db, f) = fixture(false);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let records = peers(&before);
        let runner = StopWriter::new(&f, true);
        assert!(transfer(&db, &runner, &before, &records).unwrap().is_some());
        assert!(pending_active_replacement_retirement(&db)
            .unwrap()
            .is_none());
        if cold {
            *f.0.lock().unwrap() = Firmware {
                boot: "34343434-3434-3434-3434-343434343434".into(),
                watch_flow: Some((CLIENT, DEST)),
                local: "2: br0 inet 203.0.113.1/24 scope global".into(),
                ..Default::default()
            };
            assert!(operate_at(
                &db,
                &f,
                Operation::Recover,
                nfqws2_awg_profile::now(),
                |_, _| Err(io::ErrorKind::WouldBlock.into())
            )
            .is_err());
            let mut fw = f.0.lock().unwrap();
            assert!(fw.stops.is_empty() && fw.changes == 0);
            fw.local.clear();
        }
        operate_at(
            &db,
            &f,
            Operation::Recover,
            nfqws2_awg_profile::now(),
            |_, _| Err(io::ErrorKind::WouldBlock.into()),
        )
        .unwrap();
        {
            let fw = f.0.lock().unwrap();
            assert!(!fw.leaked && fw.stops.len() == 1);
            assert_eq!(fw.forward(CLIENT, DEST), "blackhole");
        }
        assert!(pending_active_replacement_retirement(&db)
            .unwrap()
            .is_none());
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["routing"]["killswitch"],
            false
        );
        if teardown {
            operate_at(
                &db,
                &f,
                Operation::Teardown,
                nfqws2_awg_profile::now(),
                |_, _| panic!("explicit teardown should not probe"),
            )
            .unwrap();
            assert!(Journal::read(&db).unwrap().idle());
            // Simulate losing the acknowledgement after the teardown journal
            // and kernel state were already committed.
            let mut receipt = db.read_runtime::<Value>(LEASE, 64 << 10).unwrap();
            assert_eq!(receipt["temporary_stop"]["teardown"], true);
            receipt["temporary_stop"]["released"] = json!(false);
            db.transaction(|tx| tx.save_runtime_bounded(LEASE, &receipt, 64 << 10))
                .unwrap();
            let writes = f.0.lock().unwrap().changes;
            operate_at(
                &db,
                &f,
                Operation::Recover,
                nfqws2_awg_profile::now(),
                |_, _| panic!("teardown replay must not restore routing"),
            )
            .unwrap();
            assert!(Journal::read(&db).unwrap().idle());
            assert_eq!(f.0.lock().unwrap().changes, writes);
        } else {
            operate_at(
                &db,
                &f,
                Operation::Recover,
                nfqws2_awg_profile::now(),
                replacement_peer,
            )
            .unwrap();
            assert_eq!(f.0.lock().unwrap().forward(CLIENT, DEST), "awg1");
            assert!(!f.0.lock().unwrap().leaked);
        }
        assert!(f.0.lock().unwrap().stops.is_empty());
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap().as_ref(),
            Some(&records[0].owner)
        );
    }
}

#[test]
fn temporary_stop_rejects_foreign_stop_without_start_or_route_writes() {
    let (_tmp, db, f) = fixture(false);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let old = Journal::read(&db).unwrap();
    let records = peers(&before);
    let changes = f.0.lock().unwrap().changes;
    f.0.lock().unwrap().foreign_rule = "69: from all to 203.0.113.0/24 blackhole".into();
    assert!(launch_preflight(&db, &f, &before, &records[0], None).is_err());
    assert!(transfer(&db, &f, &before, &records).is_err());
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    assert!(!active_replacement_in_progress(&db).unwrap());
}

struct WatchBoth<'a> {
    inner: &'a Fake,
}

impl Runner for WatchBoth<'_> {
    fn run(&self, prog: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        let result = self.inner.run(prog, args, deadline);
        let fw = self.inner.0.lock().unwrap();
        for dest in [DEST, SECOND_DEST] {
            assert_ne!(fw.forward(CLIENT, dest), "wan0", "{prog} {args:?}");
        }
        result
    }
}

#[test]
fn multiple_ipv4_cidrs_move_together_with_optional_modes_and_exact_stop_sets() {
    for killswitch in [false, true] {
        for separate in [false, true] {
            let (_tmp, db, f) = multi_prefix_fixture(killswitch, separate);
            let before = nfqws2_awg_profile::read(&db).unwrap();
            let records = peers(&before);
            let runner = WatchBoth { inner: &f };
            let predecessor = Journal::read(&db).unwrap();
            launch_preflight(&db, &runner, &before, &records[0], None).unwrap();
            launch_preflight(&db, &runner, &before, &records[0], Some(&records[1])).unwrap();
            assert_eq!(Journal::read(&db).unwrap(), predecessor);
            assert_eq!(transfer(&db, &runner, &before, &records).unwrap(), None);
            let doc = nfqws2_awg_profile::read(&db).unwrap();
            let old_zones = &before["servers"][0]["config"]["routing"]["zones"];
            let zones = &doc["servers"][0]["config"]["routing"]["zones"];
            assert_eq!(
                zones.as_array().unwrap().len(),
                if separate { 2 } else { 1 }
            );
            for (i, z) in zones.as_array().unwrap().iter().enumerate() {
                assert_eq!(z["tunnel_id"], TARGET);
                assert_eq!(z["name"], old_zones[i]["name"]);
                assert_eq!(z["ips"], old_zones[i]["ips"]);
                assert_eq!(z["order"], i + 1);
            }
            assert_eq!(doc["routing"]["killswitch"], killswitch);
            assert_eq!(
                doc["servers"][0]["config"]["client"]["double_tunnel_mode"],
                before["servers"][1]["config"]["client"]["double_tunnel_mode"]
            );
            let installed = Journal::read(&db).unwrap();
            assert_eq!(installed.installed, installed.committed);
            assert_eq!(installed.installed.prefixes.len(), 2);
            assert_eq!(installed.installed.killswitch, killswitch);
            assert!(inspect(&db, &runner).unwrap().ready);
            let cleanup = active_replacement_launch_cleanup(&db).unwrap().unwrap();
            assert!(!cleanup.stop);
            finish_active_replacement_launch_cleanup(&db, &cleanup).unwrap();
            assert_eq!(
                pending_active_replacement_retirement(&db).unwrap().as_ref(),
                Some(&records[0].owner)
            );
            let fw = f.0.lock().unwrap();
            assert_eq!(fw.stops.len(), if killswitch { 2 } else { 0 });
            for dest in [DEST, SECOND_DEST] {
                assert_eq!(fw.forward(CLIENT, dest), "awg1");
            }
        }
    }
}

#[test]
fn multiple_ipv4_cidrs_stay_protected_through_each_failed_unguarded_write() {
    let writes = {
        let (_tmp, db, f) = multi_prefix_fixture(false, true);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let baseline = f.0.lock().unwrap().changes;
        transfer(&db, &WatchBoth { inner: &f }, &before, &peers(&before)).unwrap();
        let count = f.0.lock().unwrap().changes - baseline;
        count
    };
    for index in 1..=writes {
        let (_tmp, db, f) = multi_prefix_fixture(false, false);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        {
            let mut fw = f.0.lock().unwrap();
            fw.fail_after = Some(fw.changes + index);
        }
        let runner = WatchBoth { inner: &f };
        let (id, device) = match transfer(&db, &runner, &before, &peers(&before)) {
            Ok(warning) => {
                assert!(warning.is_some(), "write {index}");
                (TARGET, "awg1")
            }
            Err(_) => {
                let fw = f.0.lock().unwrap();
                for dest in [DEST, SECOND_DEST] {
                    assert_eq!(fw.forward(CLIENT, dest), "awg0", "write {index}");
                }
                assert!(fw.stops.is_empty(), "write {index}");
                (SOURCE, "awg0")
            }
        };
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(doc["active_id"], id);
        assert_eq!(doc["routing"]["killswitch"], false);
        operate_at(
            &db,
            &runner,
            Operation::Recover,
            nfqws2_awg_profile::now(),
            replacement_peer,
        )
        .unwrap();
        let fw = f.0.lock().unwrap();
        assert!(fw.stops.is_empty(), "write {index}");
        for dest in [DEST, SECOND_DEST] {
            assert_eq!(fw.forward(CLIENT, dest), device, "write {index}");
        }
    }
}

#[test]
fn multiple_ipv4_cidrs_require_every_grant_before_launch_or_route_write() {
    let (_tmp, db, f) = multi_prefix_fixture(false, true);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let baseline = f.0.lock().unwrap().changes;
    let mut records = peers(&before);
    records[1].allowed = vec!["203.0.113.0/24".into()];
    assert!(launch_preflight(&db, &f, &before, &records[0], Some(&records[1])).is_err());
    assert!(transfer(&db, &f, &before, &records).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][1]["config"]["peers"][0]["allowed_ips"] = json!("203.0.113.0/24");
        Ok(())
    })
    .unwrap();
    let limited = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&limited);
    assert!(launch_preflight(&db, &f, &limited, &records[0], None).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), limited);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][1]["config"]["peers"][0]["allowed_ips"] = json!("0.0.0.0/0");
        doc["servers"][1]["config"]["client"]["double_tunnel_id"] = json!(SOURCE);
        Ok(())
    })
    .unwrap();
    let nested = nfqws2_awg_profile::read(&db).unwrap();
    assert!(launch_preflight(&db, &f, &nested, &records[0], None).is_err());
    assert!(transfer(&db, &f, &nested, &peers(&nested)).is_err());
    assert_eq!(f.0.lock().unwrap().changes, baseline);
    assert!(!active_replacement_in_progress(&db).unwrap());
}

#[test]
fn multiple_ipv4_cidrs_remain_parked_until_every_live_path_is_recovered() {
    let (_tmp, db, f) = multi_prefix_fixture(false, true);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&before);
    let failed_release = StopWriter::new(&f, true);
    let result = transfer(&db, &failed_release, &before, &records).unwrap();
    assert!(result.is_some());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap()["active_id"], TARGET);
    let runner = WatchBoth { inner: &f };
    operate_at(
        &db,
        &runner,
        Operation::Recover,
        nfqws2_awg_profile::now(),
        |row, iface| {
            let mut live = replacement_peer(row, iface)?;
            live.allowed = vec!["203.0.113.0/24".into()];
            Ok(live)
        },
    )
    .unwrap();
    {
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.stops.len(), 2);
        for dest in [DEST, SECOND_DEST] {
            assert_eq!(fw.forward(CLIENT, dest), "blackhole");
        }
    }
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());
    operate_at(
        &db,
        &runner,
        Operation::Recover,
        nfqws2_awg_profile::now(),
        replacement_peer,
    )
    .unwrap();
    assert_eq!(
        pending_active_replacement_retirement(&db).unwrap().unwrap(),
        records[0].owner
    );
    let fw = f.0.lock().unwrap();
    assert!(fw.stops.is_empty());
    for dest in [DEST, SECOND_DEST] {
        assert_eq!(fw.forward(CLIENT, dest), "awg1");
    }
}

#[test]
fn hot_replacement_preserves_configured_optional_outer_and_routes() {
    for killswitch in [false, true] {
        for modes in [
            ["automatic", "preferred"],
            ["preferred", "last_resort"],
            ["last_resort", "automatic"],
        ] {
            let (_tmp, db, f) = optional_outer_fixture(killswitch, modes);
            let before = nfqws2_awg_profile::read(&db).unwrap();
            let records = peers(&before);
            let runner = WatchBoth { inner: &f };
            let old = Journal::read(&db).unwrap();
            assert!(launch_preflight(&db, &runner, &before, &records[0], None).is_err());
            assert!(!active_replacement_in_progress(&db).unwrap());
            assert_eq!(Journal::read(&db).unwrap(), old);
            assert_eq!(transfer(&db, &runner, &before, &records).unwrap(), None);
            let doc = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(doc["routing"]["killswitch"], killswitch);
            assert_eq!(doc["active_id"], TARGET);
            assert_eq!(
                doc["servers"][0]["config"]["client"]["double_tunnel_mode"],
                modes[1]
            );
            assert_eq!(
                doc["servers"][0]["config"]["client"]["double_tunnel_id"],
                OUTER
            );
            assert_eq!(doc["servers"][1], before["servers"][2]);
            assert!(inspect(&db, &runner).unwrap().ready);
            assert!(active_replacement_launch_cleanup(&db).unwrap().is_none());
            assert_eq!(
                pending_active_replacement_retirement(&db).unwrap().unwrap(),
                records[0].owner
            );
            let fw = f.0.lock().unwrap();
            assert_eq!(fw.stops.len(), if killswitch { 2 } else { 0 });
            for dest in [DEST, SECOND_DEST] {
                assert_eq!(fw.forward(CLIENT, dest), "awg1");
            }
        }
    }
}

#[test]
fn configured_optional_outer_rejects_nested_and_changed_paths() {
    for killswitch in [false, true] {
        let (_tmp, db, f) = optional_outer_fixture(killswitch, ["automatic", "last_resort"]);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let mut records = peers(&before);
        let original = f.0.lock().unwrap().changes;
        records[1].socket_mark = 0xA021_0000;
        assert!(transfer(&db, &f, &before, &records).is_err());
        records[1].socket_mark = 0;
        let mut after = candidate(&before);
        after["servers"][1]["config"]["endpoint"] = json!("198.51.100.13:443");
        assert!(db
            .transaction(|tx| {
                replace_active_profile(&db, tx, &f, &before, &after, &records, &["wan0".into()])
            })
            .is_err());
        let mut after = candidate(&before);
        after["servers"][0]["config"]["client"]["double_tunnel_id"] = json!("");
        assert!(db
            .transaction(|tx| {
                replace_active_profile(&db, tx, &f, &before, &after, &records, &["wan0".into()])
            })
            .is_err());
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert!(!active_replacement_in_progress(&db).unwrap());
        assert_eq!(f.0.lock().unwrap().changes, original);
    }
}

fn recover_native(
    db: &Store,
    run: &dyn Runner,
    owner: Option<&ActiveReplacementPeer>,
) -> io::Result<()> {
    operate_at(
        db,
        run,
        Operation::Recover,
        nfqws2_awg_profile::now(),
        |row, iface| Ok(replacement_peer(row, iface)?.with_active_replacement_peer(owner.cloned())),
    )
}

#[test]
fn optional_outer_precommit_failure_restores_exact_owned_source() {
    let (_tmp, db, f) = optional_outer_fixture(false, ["automatic", "last_resort"]);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let prior = Journal::read(&db).unwrap();
    {
        let mut fw = f.0.lock().unwrap();
        fw.fail_after = Some(fw.changes + 1);
    }
    let w = WatchBoth { inner: &f };
    assert!(transfer(&db, &w, &before, &peers(&before)).is_err());
    assert_eq!(Journal::read(&db).unwrap(), prior);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    assert!(!active_replacement_in_progress(&db).unwrap());
    let fw = f.0.lock().unwrap();
    assert!(fw.stops.is_empty());
    for dest in [DEST, SECOND_DEST] {
        assert_eq!(fw.forward(CLIENT, dest), "awg0");
    }
}

#[test]
fn optional_outer_lost_release_ack_requires_current_owner_and_exact_policy() {
    let (_tmp, db, f) = optional_outer_fixture(false, ["automatic", "last_resort"]);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&before);
    let w = WatchBoth { inner: &f };
    assert_eq!(transfer(&db, &w, &before, &records).unwrap(), None);
    let mut receipt: Value = db.read_runtime(LEASE, 64 << 10).unwrap();
    assert_eq!(receipt["temporary_stop"]["released"], true);
    assert!(receipt["temporary_stop"]["transport_policy"].is_object());
    receipt["temporary_stop"]["released"] = json!(false);
    db.transaction(|tx| tx.save_runtime_bounded(LEASE, &receipt, 64 << 10))
        .unwrap();
    assert!(active_replacement_native_witness_needed(&db, "awg1").unwrap());
    assert!(!active_replacement_native_witness_needed(&db, "awg2").unwrap());

    recover_native(&db, &w, None).unwrap();
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());
    {
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.stops.len(), 2);
        assert_eq!(fw.forward(CLIENT, DEST), "blackhole");
        assert_eq!(fw.forward(CLIENT, SECOND_DEST), "blackhole");
    }
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["double_tunnel_mode"] = json!("preferred");
        Ok(())
    })
    .unwrap();
    recover_native(&db, &w, Some(&records[1])).unwrap();
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());
    assert_eq!(f.0.lock().unwrap().stops.len(), 2);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][0]["config"]["client"]["double_tunnel_mode"] = json!("last_resort");
        Ok(())
    })
    .unwrap();

    let mut edited = receipt.clone();
    let digest = edited["temporary_stop"]["transport_policy"]["target"]
        .as_array_mut()
        .unwrap();
    digest[0] = json!(digest[0].as_u64().unwrap() ^ 1);
    db.transaction(|tx| tx.save_runtime_bounded(LEASE, &edited, 64 << 10))
        .unwrap();
    assert!(recover_native(&db, &w, Some(&records[1])).is_err());
    assert_eq!(f.0.lock().unwrap().stops.len(), 2);
    db.transaction(|tx| tx.save_runtime_bounded(LEASE, &receipt, 64 << 10))
        .unwrap();

    recover_native(&db, &w, Some(&records[1])).unwrap();
    assert!(!active_replacement_native_witness_needed(&db, "awg1").unwrap());
    assert_eq!(
        pending_active_replacement_retirement(&db).unwrap().unwrap(),
        records[0].owner
    );
    let fw = f.0.lock().unwrap();
    assert!(fw.stops.is_empty());
    assert_eq!(fw.forward(CLIENT, DEST), "awg1");
    assert_eq!(fw.forward(CLIENT, SECOND_DEST), "awg1");
}

#[test]
fn optional_outer_cold_recovery_parks_stale_and_nested_owners() {
    let (_tmp, db, f) = optional_outer_fixture(false, ["preferred", "automatic"]);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let records = peers(&before);
    assert!(transfer(&db, &StopWriter::new(&f, true), &before, &records)
        .unwrap()
        .is_some());
    *f.0.lock().unwrap() = Firmware {
        boot: REBOOT.into(),
        ..Default::default()
    };
    recover_native(&db, &f, Some(&records[1])).unwrap();
    assert_eq!(f.0.lock().unwrap().stops.len(), 2);
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());

    let w = WatchBoth { inner: &f };
    let mut current = records[1].clone();
    current.owner.boot = REBOOT.into();
    current.owner.pid += 1;
    current.owner.started += 1;
    current.owner.receipt_sha256 = [41; 32];
    operate_at(
        &db,
        &w,
        Operation::Recover,
        nfqws2_awg_profile::now(),
        |row, iface| {
            let mut peer =
                replacement_peer(row, iface)?.with_active_replacement_peer(Some(current.clone()));
            peer.socket_mark = 0xa021_0000;
            peer.nested_mtu = Some(1280);
            Ok(peer)
        },
    )
    .unwrap();
    assert_eq!(f.0.lock().unwrap().stops.len(), 2);
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());

    recover_native(&db, &w, Some(&current)).unwrap();
    let fw = f.0.lock().unwrap();
    assert!(fw.stops.is_empty());
    assert_eq!(fw.forward(CLIENT, DEST), "awg1");
    assert_eq!(fw.forward(CLIENT, SECOND_DEST), "awg1");
}

struct NestedSourceWriter<'a> {
    inner: StopWriter<'a>,
    live: AtomicBool,
    partial: AtomicBool,
}

impl Runner for NestedSourceWriter<'_> {
    fn run(&self, prog: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        assert!(!matches!(
            args,
            ["-4" | "-6", "rule", "add" | "del", "pref", "60" | "61", ..]
        ));
        if self.live.load(Ordering::Relaxed) && prog == "ip" {
            if args.ends_with(&["rule", "show"]) {
                let rules = self.inner.run(prog, args, deadline)?;
                let lookup = if self.partial.load(Ordering::Relaxed) {
                    ""
                } else {
                    "60: from all fwmark 0xa0000000 lookup 828\n"
                };
                return Ok(format!(
                    "{rules}\n{lookup}61: from all fwmark 0xa0000000 prohibit\n"
                ));
            }
            if args == ["-4", "route", "get", "198.51.100.10", "mark", "0xa0000000"] {
                return Ok("198.51.100.10 dev awg2 table 828 src 192.0.2.21".into());
            }
        }
        let result = self.inner.run(prog, args, deadline);
        let fw = self.inner.inner.0.lock().unwrap();
        for dest in [DEST, SECOND_DEST] {
            assert_ne!(fw.forward(CLIENT, dest), "wan0", "{prog} {args:?}");
        }
        result
    }
}

fn nested_source_fixture(killswitch: bool) -> (tempfile::TempDir, Store, Fake) {
    let (tmp, db, f) = optional_outer_fixture(killswitch, ["automatic", "last_resort"]);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        doc["servers"][2]["config"]["client"]["standby"] = json!(false);
        Ok(())
    })
    .unwrap();
    (tmp, db, f)
}

fn nested_source_records(
    db: &Store,
    writer: &NestedSourceWriter<'_>,
) -> [ActiveReplacementPeer; 2] {
    let before = nfqws2_awg_profile::read(db).unwrap();
    let mut records = peers(&before);
    let outer = nested_fixture_underlay(&before, OUTER);
    records[0].owner.nested = Some(NativeNestedRemovalScope {
        outer_iface: outer.owner.iface.clone(),
        endpoint: records[0].endpoint.ip(),
        source: "192.0.2.21".parse().unwrap(),
    });
    records[0].socket_mark = 0xa000_0000;
    records[0].mtu = active_replacement_nested_mtu(&before, SOURCE, 1420).unwrap();
    records[0].underlay = Some(outer);
    operate_at(
        db,
        writer,
        Operation::Refresh,
        nfqws2_awg_profile::now(),
        |row, iface| nested_source_live(row, iface, &records),
    )
    .unwrap();
    records
}

fn nested_fixture_underlay(before: &Value, id: &str) -> ActiveReplacementUnderlay {
    let (iface, endpoint, fingerprint) = active_replacement_underlay_identity(before, id).unwrap();
    let identity = if id == OUTER { 202 } else { 203 };
    ActiveReplacementUnderlay {
        owner: NativeRemovalSeal {
            id: id.into(),
            iface,
            boot: BOOT.into(),
            pid: identity,
            started: u64::from(identity),
            receipt_sha256: [identity as u8; 32],
            nested: None,
        },
        fingerprint,
        endpoint,
        socket_mark: 0,
        mtu: 1420,
        allowed: vec!["198.51.100.10/32".into()],
    }
}

fn nested_source_live(
    row: &Value,
    iface: &str,
    records: &[ActiveReplacementPeer; 2],
) -> io::Result<LivePeer> {
    let native = if iface == "awg0" {
        &records[0]
    } else {
        &records[1]
    };
    let mut live = replacement_peer(row, iface)?.with_active_replacement_peer(Some(native.clone()));
    live.nested_mtu = native.owner.nested.as_ref().map(|_| native.mtu);
    live.socket_mark = native.socket_mark;
    Ok(live)
}

#[test]
fn nested_source_transfer_tracks_its_pair_until_exact_retirement() {
    for killswitch in [false, true] {
        let (_tmp, db, f) = nested_source_fixture(killswitch);
        let writer = NestedSourceWriter {
            inner: StopWriter::new(&f, false),
            live: AtomicBool::new(true),
            partial: AtomicBool::new(false),
        };
        let records = nested_source_records(&db, &writer);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(transfer(&db, &writer, &before, &records).unwrap(), None);
        let saved = nfqws2_awg_profile::read(&db).unwrap();
        assert_eq!(saved["servers"][1], before["servers"][2]);
        assert_eq!(saved["routing"]["killswitch"], killswitch);
        assert_eq!(saved["active_id"], TARGET);
        assert!(inspect(&db, &writer).unwrap().ready);
        let retiring = pending_active_replacement_retirement(&db).unwrap().unwrap();
        assert_eq!(retiring, records[0].owner);
        assert!(retiring.nested.is_some());
        writer.partial.store(true, Ordering::Relaxed);
        assert!(inspect(&db, &writer).is_err());
        assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
        assert_eq!(
            pending_active_replacement_retirement(&db).unwrap(),
            Some(retiring.clone())
        );

        writer.live.store(false, Ordering::Relaxed);
        finish_active_replacement_retirement(&db, &retiring).unwrap();
        assert!(!active_replacement_in_progress(&db).unwrap());
        assert!(inspect(&db, &writer).unwrap().ready);
        let fw = f.0.lock().unwrap();
        assert_eq!(fw.stops.len(), if killswitch { 2 } else { 0 });
        for dest in [DEST, SECOND_DEST] {
            assert_eq!(fw.forward(CLIENT, dest), "awg1");
        }
    }
}

#[test]
fn nested_source_standby_hold_is_committed_and_cleared_with_exact_retirement() {
    for killswitch in [false, true] {
        let (_tmp, db, f) = optional_outer_fixture(killswitch, ["automatic", "last_resort"]);
        let writer = NestedSourceWriter {
            inner: StopWriter::new(&f, !killswitch),
            live: AtomicBool::new(true),
            partial: AtomicBool::new(false),
        };
        let records = nested_source_records(&db, &writer);
        let before = nfqws2_awg_profile::read(&db).unwrap();
        assert!(before.get(ACTIVE_REPLACEMENT_FIELD).is_none());
        let warning = transfer(&db, &writer, &before, &records).unwrap();
        assert_eq!(warning.is_some(), !killswitch);

        let after = nfqws2_awg_profile::read(&db).unwrap();
        let outer = &records[0].underlay.as_ref().unwrap().owner;
        assert_eq!(
            after[ACTIVE_REPLACEMENT_FIELD]["retained_outer"],
            json!(outer)
        );
        assert_eq!(after["servers"][1], before["servers"][2]);
        assert_eq!(after["servers"][1]["config"]["client"]["standby"], true);
        let mut disk: Value = db.read_runtime(LEASE, 64 << 10).unwrap();
        assert_eq!(disk["retained_outer"], json!(outer));
        let saved = disk.clone();
        disk["retained_outer"]["started"] = json!(outer.started + 1);
        db.transaction(|tx| tx.save_runtime_bounded(LEASE, &disk, 64 << 10))
            .unwrap();
        assert!(pending_active_replacement_retirement(&db).is_err());
        db.transaction(|tx| tx.save_runtime_bounded(LEASE, &saved, 64 << 10))
            .unwrap();

        if !killswitch {
            assert!(pending_active_replacement_retirement(&db)
                .unwrap()
                .is_none());
            recover_native(&db, &writer, Some(&records[1])).unwrap();
        }
        let source = pending_active_replacement_retirement(&db).unwrap().unwrap();
        assert_eq!(source, records[0].owner);
        writer.live.store(false, Ordering::Relaxed);
        finish_active_replacement_retirement(&db, &source).unwrap();
        let settled = nfqws2_awg_profile::read(&db).unwrap();
        assert!(settled.get(ACTIVE_REPLACEMENT_FIELD).is_none());
        assert_eq!(settled["servers"][1], before["servers"][2]);
    }
}

struct SharedNestedWriter<'a> {
    source: NestedSourceWriter<'a>,
    target_live: AtomicBool,
    cold: AtomicBool,
    target_outer: &'static str,
}

impl Runner for SharedNestedWriter<'_> {
    fn run(&self, prog: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        let run = || {
            if self.cold.load(Ordering::Relaxed) {
                self.source.inner.run(prog, args, deadline)
            } else {
                self.source.run(prog, args, deadline)
            }
        };
        if self.target_live.load(Ordering::Relaxed) && prog == "ip" {
            if args.ends_with(&["rule", "show"]) {
                let rules = run()?;
                return Ok(format!(
                    "{rules}\n60: from all fwmark 0xa0000001 lookup 829\n61: from all fwmark 0xa0000001 prohibit\n"
                ));
            }
            if args == ["-4", "route", "get", "198.51.100.11", "mark", "0xa0000001"] {
                return Ok(format!(
                    "198.51.100.11 dev {} table 829 src 192.0.2.21",
                    self.target_outer
                ));
            }
        }
        run()
    }
}

#[test]
fn shared_nested_transfer_attests_both_selectors_and_settles_exact_successor() {
    transfer_to_nested_successor(NestedSource::SharedOuter);
}

#[test]
fn direct_source_transfer_requires_exact_nested_successor_and_retains_its_outer() {
    transfer_to_nested_successor(NestedSource::Direct);
}

#[test]
fn nested_transfer_pins_each_independent_outer_for_owned_rollback_and_settlement() {
    transfer_to_nested_successor(NestedSource::DistinctOuter);
}

#[test]
fn nested_successor_keeps_only_the_independent_standby_source_outer_until_retirement() {
    transfer_to_nested_successor(NestedSource::DistinctStandbyOuter);
}

#[derive(Default)]
struct PermanentReplacementRouter {
    marked: packed::Router,
    fences: Mutex<BTreeSet<u16>>,
    audit: AtomicBool,
    target: AtomicBool,
    retired: AtomicBool,
    plain_inner_lost: AtomicBool,
    outer_lost: AtomicBool,
    original_direct_unguarded: bool,
}

impl PermanentReplacementRouter {
    fn classified(&self, dest: &str) -> (String, u16) {
        let mark = self
            .marked
            .packet_mark(CLIENT, dest)
            .expect("payload classified");
        let mark = mark.split('/').next().unwrap();
        let mark_bits = u32::from_str_radix(mark.trim_start_matches("0x"), 16).unwrap();
        let slot = ((mark_bits >> 20) & 0xff) as u16;
        (mark.to_owned(), 18000 + slot)
    }

    fn payload(&self, dest: &str) -> String {
        let (mark, _) = self.classified(dest);
        self.marked
            .run(
                "ip",
                &["-4", "route", "get", dest, "mark", &mark],
                Instant::now(),
            )
            .unwrap()
    }

    fn check(&self, releasing_original: bool) {
        if self.audit.load(Ordering::Relaxed) {
            let path = self.payload(DEST);
            assert!(
                path.ends_with(" dev awg0") || path.ends_with(" dev awg1"),
                "{path}"
            );
            let (_, table) = self.classified(DEST);
            assert!(
                self.fences.lock().unwrap().contains(&table)
                    || releasing_original
                        && self.original_direct_unguarded
                        && path.ends_with(" dev awg0")
            );
        }
    }
}

impl Runner for PermanentReplacementRouter {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if program == "ip" {
            if let ["-4", "route", op @ ("add" | "del"), "blackhole", "default", "table", table, "proto", "242", "metric", "1000"] =
                args
            {
                let table = table.parse().unwrap();
                if *op == "add" {
                    assert!(self.fences.lock().unwrap().insert(table));
                } else {
                    assert!(self.fences.lock().unwrap().remove(&table));
                }
                self.check(*op == "del");
                return Ok(String::new());
            }
            if args.ends_with(&["route", "show", "table", "all"]) && args.contains(&"-4") {
                let mut routes = self.marked.run(program, args, deadline)?;
                for table in &*self.fences.lock().unwrap() {
                    routes.push_str(&format!(
                        "\nblackhole default table {table} proto 242 metric 1000"
                    ));
                }
                return Ok(routes);
            }
            if args.ends_with(&["rule", "show"]) {
                let mut rules = self.marked.run(program, args, deadline)?;
                if !self.retired.load(Ordering::Relaxed) {
                    rules.push_str("\n60: from all fwmark 0xa0000000 lookup 828\n61: from all fwmark 0xa0000000 prohibit\n");
                }
                if self.target.load(Ordering::Relaxed) {
                    rules.push_str("\n60: from all fwmark 0xa0000001 lookup 829\n61: from all fwmark 0xa0000001 prohibit\n");
                }
                return Ok(rules);
            }
            match args {
                ["-4", "route", "get", "198.51.100.10" | "198.51.100.11"]
                    if self.plain_inner_lost.load(Ordering::Relaxed) =>
                {
                    return Err(io::ErrorKind::NetworkUnreachable.into())
                }
                ["-4", "route", "get", "198.51.100.13"]
                    if self.outer_lost.load(Ordering::Relaxed) =>
                {
                    return Err(io::ErrorKind::NetworkUnreachable.into())
                }
                ["-4", "route", "get", "198.51.100.10", "mark", "0xa0000000"] => {
                    return Ok("198.51.100.10 dev awg2 table 828 src 192.0.2.22".into())
                }
                ["-4", "route", "get", "198.51.100.11", "mark", "0xa0000001"] => {
                    return Ok("198.51.100.11 dev awg3 table 829 src 192.0.2.23".into())
                }
                _ => (),
            }
        }
        let result = self.marked.run(program, args, deadline);
        if program == "ip"
            && matches!(
                args,
                ["-4", "rule" | "route", "add" | "del" | "replace", ..]
            )
        {
            assert!(
                !matches!(args, ["-4", "rule", _, "pref", "69", ..]),
                "intrinsic fences require no temporary plain Stop"
            );
            self.check(false);
        }
        result
    }

    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        deadline: Instant,
    ) -> io::Result<String> {
        let result = self.marked.run_input(program, args, input, deadline);
        self.check(false);
        result
    }
}

#[test]
fn permanent_nested_pair_switches_exact_classifier_and_rolls_back_lost_ack() {
    permanent_nested_pair(false, false);
}

#[test]
fn permanent_nested_pair_keeps_outer_wan_after_plain_inner_paths_disappear() {
    permanent_nested_pair(true, false);
}

#[test]
fn marked_direct_source_keeps_guard_until_permanent_successor_is_ready() {
    permanent_nested_pair(false, true);
}

#[test]
fn permanent_source_transfer_seals_its_original_outer_for_direct_successor() {
    let (_tmp, db, mut records) = permanent_profiles(true, false);
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[1]["config"]["client"]["double_tunnel_mode"] = json!("automatic");
        rows[1]["config"]["client"]["double_tunnel_id"] = json!("");
        rows.retain(|row| row["id"] != TARGET_OUTER);
        Ok(())
    })
    .unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    records[1] = peers(&doc)[1].clone();
    let router = PermanentReplacementRouter::default();
    for op in [Operation::Apply, Operation::Commit] {
        operate_at(&db, &router, op, nfqws2_awg_profile::now(), |cfg, iface| {
            permanent_live(cfg, iface, &records)
        })
        .unwrap();
    }
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let old = Journal::read(&db).unwrap();
    let slot = old.installed.marks["awg0"];
    router.audit.store(true, Ordering::Relaxed);
    router.marked.fail_switch.store(true, Ordering::Relaxed);
    assert!(transfer(&db, &router, &before, &records).is_err());
    assert!(!router.marked.fail_switch.load(Ordering::Relaxed));
    assert_eq!(Journal::read(&db).unwrap(), old);
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    transfer(&db, &router, &before, &records).unwrap();
    let next = Journal::read(&db).unwrap();
    assert_ne!(next.installed.marks["awg1"], slot);
    assert!(next.installed.permanent_fences.is_empty());
    assert!(next.installed.killswitch);
    assert!(router.payload(DEST).ends_with(" dev awg1"));
    let lease: Value = db.read_runtime(LEASE, 64 << 10).unwrap();
    let underlay = records[0].underlay.as_ref().unwrap();
    assert_eq!(
        lease["retiring_nested"]["outer"]["owner"],
        json!(underlay.owner)
    );
    assert_eq!(
        lease["retiring_nested"]["outer"]["fingerprint"],
        json!(underlay.fingerprint)
    );
    assert_eq!(lease["retiring_nested"]["target"], json!(records[1].owner));
    assert!(lease.get("temporary_stop").is_none());
    let mut changed = lease.clone();
    changed["retiring_nested"]["outer"]["fingerprint"] = serde_json::to_value([5u8; 32]).unwrap();
    db.transaction(|tx| tx.save_runtime_bounded(LEASE, &changed, 64 << 10))
        .unwrap();
    assert!(pending_active_replacement_retirement(&db).is_err());
    db.transaction(|tx| tx.save_runtime_bounded(LEASE, &lease, 64 << 10))
        .unwrap();
    router.retired.store(true, Ordering::Relaxed);
    finish_active_replacement_retirement(&db, &records[0].owner).unwrap();
    assert!(inspect(&db, &router).unwrap().ready);
}

#[test]
fn initial_policy_exempts_only_verified_unselected_permanent_transport_from_plain_wan() {
    for killswitch in [false, true] {
        let (_tmp, db, mut peers) = permanent_profiles(killswitch, false);
        assert!(Journal::read(&db).unwrap().idle());
        let doc = nfqws2_awg_profile::read(&db).unwrap();
        let router = PermanentReplacementRouter::default();
        router.target.store(true, Ordering::Relaxed);
        router.plain_inner_lost.store(true, Ordering::Relaxed);
        peers[1].nested_only = true;
        let kernel = kernel(&router);
        let resolve = |doc: &Value, peers: &[ActiveReplacementPeer; 2]| {
            let intent = plan::compile_effective(
                doc,
                crate::policy::current(doc).unwrap(),
                None,
                true,
                &[],
                Default::default(),
            )
            .unwrap();
            plan::resolve_on(
                doc,
                intent,
                false,
                None,
                Some(plan::Verification::Read(&kernel)),
                |cfg, iface| permanent_live(cfg, iface, peers),
            )
            .unwrap()
        };
        let confirmed = resolve(&doc, &peers);
        assert_eq!(confirmed.plan.targets.len(), 1);
        assert!(confirmed.plan.fully_live());
        assert!(confirmed.plan.targets.contains_key("awg0"));
        assert!(!confirmed.endpoints.contains(&peers[1].endpoint.ip()));
        for peer in &peers {
            assert!(confirmed
                .endpoints
                .contains(&peer.underlay.as_ref().unwrap().endpoint.ip()));
        }
        kernel.guard(&confirmed.plan, &confirmed.endpoints).unwrap();

        let mut raw_alias = doc.clone();
        let rows = raw_alias["servers"].as_array_mut().unwrap();
        let mut alias = rows[3].clone();
        alias["id"] = json!("planned-alias");
        alias["config"]["enabled"] = json!(false);
        alias["config"]["client_iface"] = json!("awg1");
        rows.push(alias);
        let mut wrong_scope = peers.clone();
        wrong_scope[1].owner.nested.as_mut().unwrap().source = "192.0.2.25".parse().unwrap();
        for negative in [resolve(&raw_alias, &peers), resolve(&doc, &wrong_scope)] {
            assert!(negative.endpoints.contains(&peers[1].endpoint.ip()));
            assert!(kernel.guard(&negative.plan, &negative.endpoints).is_err());
        }
        router.outer_lost.store(true, Ordering::Relaxed);
        let unavailable = resolve(&doc, &peers);
        assert!(unavailable.endpoints.contains(&peers[1].endpoint.ip()));
        assert!(kernel
            .guard(&unavailable.plan, &unavailable.endpoints)
            .is_err());
        assert!(Journal::read(&db).unwrap().idle());
    }
}

fn permanent_profiles(
    killswitch: bool,
    direct_source: bool,
) -> (tempfile::TempDir, Store, [ActiveReplacementPeer; 2]) {
    let (tmp, db, _) = profile_fixture(
        killswitch,
        json!([{"name":"protected", "enabled":true, "ips":["203.0.113.0/24"]}]),
        [
            if direct_source {
                "automatic"
            } else {
                "permanent"
            },
            "permanent",
        ],
    );
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        rows[1]["config"]["client"]["standby"] = json!(false);
        for (index, id) in [OUTER, TARGET_OUTER].into_iter().enumerate() {
            if direct_source && index == 0 {
                continue;
            }
            let mut outer = rows[index].clone();
            outer["id"] = json!(id);
            outer["config"]["client_iface"] = json!(format!("awg{}", index + 2));
            outer["config"]["endpoint"] = json!(format!("198.51.100.{}:443", index + 12));
            outer["config"]["client"]["double_tunnel_mode"] = json!("off");
            outer["config"]["routing"]["zones"] = json!([]);
            rows[index]["config"]["client"]["double_tunnel_id"] = json!(id);
            rows.push(outer);
        }
        Ok(())
    })
    .unwrap();
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    let mut records = peers(&doc);
    for (index, (peer, id)) in records.iter_mut().zip([OUTER, TARGET_OUTER]).enumerate() {
        if direct_source && index == 0 {
            continue;
        }
        let mut outer = nested_fixture_underlay(&doc, id);
        outer.allowed = vec![format!("{}/32", peer.endpoint.ip())];
        peer.owner.nested = Some(NativeNestedRemovalScope {
            outer_iface: outer.owner.iface.clone(),
            endpoint: peer.endpoint.ip(),
            source: format!("192.0.2.{}", index + 22).parse().unwrap(),
        });
        peer.socket_mark = 0xa000_0000 | index as u32;
        peer.mtu = active_replacement_nested_mtu(&doc, &peer.owner.id, outer.mtu).unwrap();
        peer.underlay = Some(outer);
    }
    (tmp, db, records)
}

fn permanent_live(
    cfg: &Value,
    iface: &str,
    records: &[ActiveReplacementPeer; 2],
) -> io::Result<LivePeer> {
    let mut live = nested_source_live(cfg, iface, records)?;
    let peer = &records[usize::from(iface == "awg1")];
    live.nested_transport =
        peer.underlay
            .as_ref()
            .map(|outer| nfqws2_awg_profile::RoutedNestedTransport {
                peer: nfqws2_awg_profile::RoutedMtuPeer {
                    iface: iface.into(),
                    outer_id: outer.owner.id.clone(),
                    outer_iface: outer.owner.iface.clone(),
                    endpoint: peer.endpoint,
                    effective_mtu: peer.mtu,
                    socket_mark: peer.socket_mark,
                },
                outer_endpoint: outer.endpoint,
            });
    Ok(live)
}

fn permanent_nested_pair(lose_plain: bool, direct_source: bool) {
    for killswitch in [false, true] {
        let (_tmp, db, mut records) = permanent_profiles(killswitch, direct_source);
        let read_peer = |cfg: &Value, iface: &str| permanent_live(cfg, iface, &records);
        let router = PermanentReplacementRouter {
            original_direct_unguarded: direct_source && !killswitch,
            retired: AtomicBool::new(direct_source),
            ..Default::default()
        };
        for op in [Operation::Apply, Operation::Commit] {
            operate_at(&db, &router, op, nfqws2_awg_profile::now(), read_peer).unwrap();
        }
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let original = Journal::read(&db).unwrap();
        let original_slot = original.installed.marks["awg0"];
        assert_eq!(
            original.installed.permanent_fences.contains("awg0"),
            !direct_source
        );
        assert_eq!(
            router
                .fences
                .lock()
                .unwrap()
                .contains(&(18000 + u16::from(original_slot))),
            !direct_source || killswitch
        );
        router.target.store(true, Ordering::Relaxed);
        router.audit.store(true, Ordering::Relaxed);
        if lose_plain {
            router.plain_inner_lost.store(true, Ordering::Relaxed);
            assert!(transfer(&db, &router, &before, &records).is_err());
            for peer in &mut records {
                peer.nested_only = true;
            }
            router.outer_lost.store(true, Ordering::Relaxed);
            assert!(transfer(&db, &router, &before, &records).is_err());
            router.outer_lost.store(false, Ordering::Relaxed);
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let rows = doc["servers"].as_array_mut().unwrap();
                let mut direct = rows[3].clone();
                direct["id"] = json!("ordinary-claim");
                direct["config"]["client_iface"] = json!("awg4");
                direct["config"]["endpoint"] = json!("198.51.100.11:8443");
                rows.push(direct);
                Ok(())
            })
            .unwrap();
            let shared = nfqws2_awg_profile::read(&db).unwrap();
            assert!(transfer(&db, &router, &shared, &records).is_err());
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc.clone_from(&before);
                Ok(())
            })
            .unwrap();
            assert_eq!(Journal::read(&db).unwrap(), original);
            assert!(!active_replacement_in_progress(&db).unwrap());
        }
        let mut unauthorized = records.clone();
        unauthorized[1].owner.nested = None;
        unauthorized[1].underlay = None;
        unauthorized[1].socket_mark = 0;
        assert!(transfer(&db, &router, &before, &unauthorized).is_err());
        router.marked.fail_switch.store(true, Ordering::Relaxed);
        assert!(transfer(&db, &router, &before, &records).is_err());
        assert!(!router.marked.fail_switch.load(Ordering::Relaxed));
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert_eq!(Journal::read(&db).unwrap(), original);
        assert!(router.payload(DEST).ends_with(" dev awg0"));
        assert!(!active_replacement_in_progress(&db).unwrap());
        transfer(&db, &router, &before, &records).unwrap();
        let after = Journal::read(&db).unwrap();
        assert_ne!(after.installed.marks["awg1"], original_slot);
        assert!(after.installed.permanent_fences.contains("awg1"));
        assert_eq!(after.installed.killswitch, killswitch);
        assert!(router.payload(DEST).ends_with(" dev awg1"));
        assert!(router.marked.packet_mark(CLIENT, SECOND_DEST).is_none());
        let lease: Value = db.read_runtime(LEASE, 64 << 10).unwrap();
        if direct_source && !killswitch {
            assert_eq!(lease["temporary_stop"]["released"], true);
            assert!(!router
                .fences
                .lock()
                .unwrap()
                .contains(&(18000 + u16::from(original_slot))));
        } else {
            assert!(lease.get("temporary_stop").is_none());
        }
        router.retired.store(true, Ordering::Relaxed);
        finish_active_replacement_retirement(&db, &records[0].owner).unwrap();
        assert!(inspect(&db, &router).unwrap().ready);
        assert!(!active_replacement_in_progress(&db).unwrap());
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NestedSource {
    Direct,
    SharedOuter,
    DistinctOuter,
    DistinctStandbyOuter,
}

fn transfer_to_nested_successor(source: NestedSource) {
    let source_is_nested = source != NestedSource::Direct;
    let distinct_outer = matches!(
        source,
        NestedSource::DistinctOuter | NestedSource::DistinctStandbyOuter
    );
    let standby_source = source == NestedSource::DistinctStandbyOuter;
    let target_outer = if distinct_outer { TARGET_OUTER } else { OUTER };
    for killswitch in [false, true] {
        let (_tmp, db, f) = nested_source_fixture(killswitch);
        if !source_is_nested {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                doc["servers"][0]["config"]["client"]["double_tunnel_id"] = json!("");
                Ok(())
            })
            .unwrap();
        }
        if distinct_outer {
            nfqws2_awg_profile::edit_document(&db, |doc| {
                let rows = doc["servers"].as_array_mut().unwrap();
                let mut outer = rows[2].clone();
                outer["id"] = json!(TARGET_OUTER);
                outer["config"]["client_iface"] = json!("awg3");
                outer["config"]["endpoint"] = json!("198.51.100.13:443");
                rows[1]["config"]["client"]["double_tunnel_id"] = json!(TARGET_OUTER);
                rows[2]["config"]["client"]["standby"] = json!(standby_source);
                rows.push(outer);
                Ok(())
            })
            .unwrap();
        }
        let writer = SharedNestedWriter {
            source: NestedSourceWriter {
                inner: StopWriter::new(&f, false),
                live: AtomicBool::new(source_is_nested),
                partial: AtomicBool::new(false),
            },
            target_live: AtomicBool::new(false),
            cold: AtomicBool::new(false),
            target_outer: if distinct_outer { "awg3" } else { "awg2" },
        };
        let mut records = if source_is_nested {
            nested_source_records(&db, &writer.source)
        } else {
            peers(&nfqws2_awg_profile::read(&db).unwrap())
        };
        let before = nfqws2_awg_profile::read(&db).unwrap();
        let mut outer = nested_fixture_underlay(&before, target_outer);
        outer.allowed.push("198.51.100.11/32".into());
        records[1].owner.nested = Some(NativeNestedRemovalScope {
            outer_iface: outer.owner.iface.clone(),
            endpoint: records[1].endpoint.ip(),
            source: "192.0.2.21".parse().unwrap(),
        });
        records[1].underlay = Some(outer);
        records[1].socket_mark = 0xa000_0001;
        records[1].mtu = active_replacement_nested_mtu(&before, TARGET, 1420).unwrap();
        writer.target_live.store(true, Ordering::Relaxed);
        let baseline = f.0.lock().unwrap().changes;
        let mut foreign = records.clone();
        if distinct_outer {
            foreign[1].underlay = records[0].underlay.clone();
        } else if source_is_nested {
            foreign[1].underlay.as_mut().unwrap().owner.pid += 1;
        } else {
            foreign[1].underlay.as_mut().unwrap().owner.iface = "awg3".into();
        }
        assert!(transfer(&db, &writer, &before, &foreign).is_err());
        let mut wrong_source = records.clone();
        wrong_source[1].owner.nested.as_mut().unwrap().source = "192.0.2.22".parse().unwrap();
        assert!(transfer(&db, &writer, &before, &wrong_source).is_err());
        assert_eq!(f.0.lock().unwrap().changes, baseline);

        f.0.lock().unwrap().fail_after = Some(baseline + 1);
        assert!(transfer(&db, &writer, &before, &records).is_err());
        assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
        assert!(!active_replacement_in_progress(&db).unwrap());
        for dest in [DEST, SECOND_DEST] {
            assert_eq!(f.0.lock().unwrap().forward(CLIENT, dest), "awg0");
        }
        if !killswitch {
            writer
                .source
                .inner
                .fail_release
                .store(true, Ordering::Relaxed);
        }
        assert_eq!(
            transfer(&db, &writer, &before, &records).unwrap().is_some(),
            !killswitch
        );
        assert_eq!(
            nfqws2_awg_profile::read(&db).unwrap()["servers"][1],
            before["servers"][2]
        );
        let lease: Value = db.read_runtime(LEASE, 64 << 10).unwrap();
        assert_eq!(
            lease["shared_nested_target"]["outer_fingerprint"],
            json!(records[1].underlay.as_ref().unwrap().fingerprint)
        );
        if distinct_outer {
            let source = records[0].underlay.as_ref().unwrap();
            assert_eq!(
                lease["shared_nested_target"]["source_outer"]["owner"],
                json!(source.owner)
            );
            assert_eq!(
                lease["shared_nested_target"]["source_outer"]["fingerprint"],
                json!(source.fingerprint)
            );
            assert_eq!(
                nfqws2_awg_profile::read(&db).unwrap()["servers"][2],
                before["servers"][3]
            );
        } else {
            assert!(lease["shared_nested_target"].get("source_outer").is_none());
        }
        if standby_source {
            let source_outer = json!(records[0].underlay.as_ref().unwrap().owner);
            let persisted = nfqws2_awg_profile::read(&db).unwrap();
            assert_eq!(
                persisted[ACTIVE_REPLACEMENT_FIELD]["retained_outer"],
                source_outer
            );
            assert_eq!(lease["retained_outer"], source_outer);
            let mut different_outer = lease.clone();
            different_outer["retained_outer"] = json!(records[1].underlay.as_ref().unwrap().owner);
            db.transaction(|tx| tx.save_runtime_bounded(LEASE, &different_outer, 64 << 10))
                .unwrap();
            assert!(pending_active_replacement_retirement(&db).is_err());
            db.transaction(|tx| tx.save_runtime_bounded(LEASE, &lease, 64 << 10))
                .unwrap();
        }

        if !killswitch {
            let mut wrong_owner = records.clone();
            if distinct_outer {
                wrong_owner[1].underlay.as_mut().unwrap().owner.started += 1;
            } else {
                wrong_owner[1].owner.started += 1;
            }
            recover_nested_transfer(&db, &writer, &wrong_owner).unwrap();
            assert!(pending_active_replacement_retirement(&db)
                .unwrap()
                .is_none());
            if source == NestedSource::SharedOuter || standby_source {
                recover_nested_transfer(&db, &writer, &records).unwrap();
            } else {
                writer.cold.store(true, Ordering::Relaxed);
                writer.source.live.store(false, Ordering::Relaxed);
                *f.0.lock().unwrap() = Firmware {
                    boot: REBOOT.into(),
                    ..Default::default()
                };
                let mut cold = records.clone();
                cold[1].owner.boot = REBOOT.into();
                cold[1].owner.started += 1;
                let outer = cold[1].underlay.as_mut().unwrap();
                outer.owner.boot = REBOOT.into();
                outer.owner.started += 1;
                let before = nfqws2_awg_profile::read(&db).unwrap();
                nfqws2_awg_profile::edit_document(&db, |doc| {
                    let index = 1 + usize::from(distinct_outer);
                    doc["servers"][index]["config"]["peers"][0]["allowed_ips"] =
                        json!("198.51.100.10/31");
                    Ok(())
                })
                .unwrap();
                let changed = nfqws2_awg_profile::read(&db).unwrap();
                outer.fingerprint = active_replacement_underlay_identity(&changed, target_outer)
                    .unwrap()
                    .2;
                assert_ne!(
                    outer.fingerprint,
                    records[1].underlay.as_ref().unwrap().fingerprint
                );
                recover_nested_transfer(&db, &writer, &cold).unwrap();
                assert!(pending_active_replacement_retirement(&db)
                    .unwrap()
                    .is_none());
                assert_eq!(f.0.lock().unwrap().stops.len(), 2);
                nfqws2_awg_profile::edit_document(&db, |doc| {
                    doc.clone_from(&before);
                    Ok(())
                })
                .unwrap();
                cold[1].underlay.as_mut().unwrap().fingerprint =
                    records[1].underlay.as_ref().unwrap().fingerprint;
                recover_nested_transfer(&db, &writer, &cold).unwrap();
            }
        }
        let source = pending_active_replacement_retirement(&db).unwrap().unwrap();
        assert_eq!(source, records[0].owner);
        writer.source.live.store(false, Ordering::Relaxed);
        finish_active_replacement_retirement(&db, &source).unwrap();
        assert!(inspect(&db, &writer).unwrap().ready);
        assert!(!active_replacement_in_progress(&db).unwrap());
        if standby_source {
            let persisted = nfqws2_awg_profile::read(&db).unwrap();
            assert!(persisted.get(ACTIVE_REPLACEMENT_FIELD).is_none());
            assert_eq!(persisted["servers"][1]["config"]["client"]["standby"], true);
        }
        for dest in [DEST, SECOND_DEST] {
            assert_eq!(f.0.lock().unwrap().forward(CLIENT, dest), "awg1");
        }
    }
}

fn recover_nested_transfer(
    db: &Store,
    run: &dyn Runner,
    sampled: &[ActiveReplacementPeer; 2],
) -> io::Result<()> {
    operate_at(
        db,
        run,
        Operation::Recover,
        nfqws2_awg_profile::now(),
        |row, iface| nested_source_live(row, iface, sampled),
    )
}

#[test]
fn nested_source_transfer_does_not_release_until_role_and_underlay_are_verified() {
    let (_tmp, db, f) = nested_source_fixture(false);
    let writer = NestedSourceWriter {
        inner: StopWriter::new(&f, false),
        live: AtomicBool::new(true),
        partial: AtomicBool::new(false),
    };
    let mut records = nested_source_records(&db, &writer);
    let before = nfqws2_awg_profile::read(&db).unwrap();
    let allowed = std::mem::take(&mut records[0].underlay.as_mut().unwrap().allowed);
    let baseline = f.0.lock().unwrap().changes;
    assert!(transfer(&db, &writer, &before, &records).is_err());
    assert_eq!(f.0.lock().unwrap().changes, baseline);
    records[0].underlay.as_mut().unwrap().allowed = allowed;
    let correct = records[0].owner.nested.as_ref().unwrap().source;
    records[0].owner.nested.as_mut().unwrap().source = "192.0.2.22".parse().unwrap();
    assert!(transfer(&db, &writer, &before, &records).is_err());
    assert_eq!(f.0.lock().unwrap().changes, baseline);
    records[0].owner.nested.as_mut().unwrap().source = correct;
    f.0.lock().unwrap().fail_after = Some(baseline + 1);
    assert!(transfer(&db, &writer, &before, &records).is_err());
    {
        let fw = f.0.lock().unwrap();
        assert!(fw.stops.is_empty());
        assert_eq!(fw.forward(CLIENT, DEST), "awg0");
    }

    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), before);
    writer.inner.fail_release.store(true, Ordering::Relaxed);
    assert!(transfer(&db, &writer, &before, &records).unwrap().is_some());
    recover_native(&db, &writer, Some(&records[0])).unwrap();
    assert!(pending_active_replacement_retirement(&db)
        .unwrap()
        .is_none());
    assert_eq!(f.0.lock().unwrap().stops.len(), 2);
    recover_native(&db, &writer, Some(&records[1])).unwrap();
    assert_eq!(
        pending_active_replacement_retirement(&db).unwrap().unwrap(),
        records[0].owner
    );
    assert!(f.0.lock().unwrap().stops.is_empty());
}
