use super::*;

const SOURCE: &str = "dormant-source";
const TARGET: &str = "dormant-target";

fn committed() -> (tempfile::TempDir, Store, Fake) {
    let (tmp, db, fake) = setup();
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let rows = doc["servers"].as_array_mut().unwrap();
        let ordinary = &mut rows[0]["config"];
        ordinary["install"] = json!("imported");
        ordinary["client"]["rust_managed"] = json!(true);
        ordinary["endpoint"] = json!("198.51.100.10:443");
        ordinary["routing"]["zones"][0]["order"] = json!(9);
        for (id, iface, ip) in [
            (SOURCE, "awg1", "198.51.100.11:443"),
            (TARGET, "awg2", "198.51.100.12:443"),
        ] {
            let mut config = ordinary_template();
            config["client_iface"] = json!(iface);
            config["endpoint"] = json!(ip);
            rows.push(json!({"id":id,"config":config}));
        }
        rows[1]["config"]["routing"]["zones"] = json!([
            {"name":"saved only","ips":["192.0.2.90/32"],"enabled":false,"order":3}
        ]);
        doc["active_id"] = json!(SOURCE);
        Ok(())
    })
    .unwrap();
    let now = nfqws2_awg_profile::now();
    action(&db, &fake, Operation::Apply, now).unwrap();
    action(&db, &fake, Operation::Commit, now).unwrap();
    (tmp, db, fake)
}

fn ordinary_template() -> Value {
    json!({
        "install":"imported", "enabled":true, "endpoint":"", "peers":[],
        "routing":{"mode":"zones","active":false,"zones":[]},
        "client":{"enabled":false,"standby":true}
    })
}

fn delete(root: &std::path::Path, db: &Store, run: &dyn Runner) -> io::Result<Option<String>> {
    let runtime = nfqws2_awg_profile::runtime::Runtime::new(root, root.join("engine"));
    runtime.delete_profile_with_route_check(
        db,
        SOURCE,
        Some(TARGET),
        |_, id| Ok(json!({"ref":id})),
        |before, after| stage_dormant_replacement(db, run, before, after, SOURCE, TARGET),
    )
}

fn assert_live(db: &Store, f: &Fake, revision: u64) {
    let s = inspect(db, f).unwrap();
    assert!(s.active && s.ready && !s.pending_commit);
    assert_eq!(s.revision, revision);
    let snapshot = FlowSnapshot::read(db, &f.0.lock().unwrap().boot).unwrap();
    let decision = snapshot.classify(
        "192.168.1.12".parse().unwrap(),
        "203.0.113.4".parse().unwrap(),
    );
    assert_eq!(decision.name, Some("mail"));
    assert_eq!(decision.rule, Some(2));
    assert_eq!(decision.rule_owner, Some("awg0"));
    assert_eq!(
        f.0.lock().unwrap().forward("192.168.1.12", "203.0.113.4"),
        "awg0"
    );
}

#[test]
fn dormant_replacement_keeps_confirmed_cidr_trace_ready_without_kernel_writes() {
    let (tmp, db, f) = committed();
    assert_live(&db, &f, 1);
    let before = Journal::read(&db).unwrap();
    let changes = f.0.lock().unwrap().changes;
    assert_eq!(delete(tmp.path(), &db, &f).unwrap(), None);
    let doc = nfqws2_awg_profile::read(&db).unwrap();
    assert_eq!(doc["active_id"], TARGET);
    assert_eq!(doc["routing_revision"], 2);
    assert!(super::super::profile_rebind::pending(&doc));
    assert_eq!(scheduled(&db).unwrap(), Schedule::Restore);
    assert_eq!(Journal::read(&db).unwrap(), before);
    assert!(finish_dormant_replacement(&db).unwrap());
    assert!(!finish_dormant_replacement(&db).unwrap());
    let after = Journal::read(&db).unwrap();
    assert_eq!(after.installed.revision, 2);
    assert_eq!(after.committed.revision, 2);
    assert_eq!(objects(&after.installed), objects(&before.installed));
    assert_eq!(f.0.lock().unwrap().changes, changes);
    assert_live(&db, &f, 2);
}

#[test]
fn dormant_replacement_recovers_profile_and_journal_write_interruptions() {
    for journal_already_saved in [false, true] {
        let (tmp, db, f) = committed();
        let changes = f.0.lock().unwrap().changes;
        delete(tmp.path(), &db, &f).unwrap();
        if journal_already_saved {
            let mut j = Journal::read(&db).unwrap();
            j.installed.revision = 2;
            j.committed.revision = 2;
            db.transaction(|tx| tx.save_runtime_bounded(RECEIPT, &j, RECEIPT_LIMIT))
                .unwrap();
        }
        action(&db, &f, Operation::Recover, nfqws2_awg_profile::now()).unwrap();
        assert_eq!(f.0.lock().unwrap().changes, changes);
        assert_live(&db, &f, 2);
        assert!(!finish_dormant_replacement(&db).unwrap());
    }
}

#[test]
fn dormant_replacement_rebinds_before_normal_cold_boot_and_keeps_a_later_draft() {
    for later_draft in [false, true] {
        let (tmp, db, f) = committed();
        delete(tmp.path(), &db, &f).unwrap();
        if later_draft {
            edit_net(&db, "192.0.2.8/32");
        }
        *f.0.lock().unwrap() = Firmware {
            boot: "34343434-3434-3434-3434-343434343434".into(),
            ..Default::default()
        };
        action(&db, &f, Operation::Recover, nfqws2_awg_profile::now()).unwrap();
        assert!(!finish_dormant_replacement(&db).unwrap());
        if later_draft {
            let s = inspect(&db, &f).unwrap();
            assert!(s.active && !s.ready && s.revision == 1);
            assert_eq!(
                f.0.lock().unwrap().forward("192.168.1.12", "192.0.2.8"),
                "wan0"
            );
        } else {
            assert_live(&db, &f, 2);
        }
    }
}

#[test]
fn dormant_replacement_rejects_different_policy_or_live_ownership_before_save() {
    struct WrongForward<'a>(&'a Fake);
    impl Runner for WrongForward<'_> {
        fn run(&self, prog: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            match (prog, args) {
                ("ip", ["-4", "route", "get", ip]) => Ok(format!("{ip} dev wan0")),
                _ => self.0.run(prog, args, deadline),
            }
        }
    }
    let (tmp, db, f) = committed();
    let old = nfqws2_awg_profile::read(&db).unwrap();
    let change_count = f.0.lock().unwrap().changes;
    assert!(delete(tmp.path(), &db, &WrongForward(&f)).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), old);
    assert_eq!(f.0.lock().unwrap().changes, change_count);

    let runtime = nfqws2_awg_profile::runtime::Runtime::new(tmp.path(), tmp.path().join("engine"));
    assert!(runtime
        .delete_profile_with_route_check(
            &db,
            "awg0",
            Some(TARGET),
            |_, _| panic!("active source"),
            |_, _| panic!("active source"),
        )
        .is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), old);

    // An untracked deployed/legacy interface must also stay untouched.
    nfqws2_awg_profile::edit_document(&db, |doc| {
        let row = &mut doc["servers"][1];
        row["applied_config"] = row["config"].clone();
        row["applied_config"]["client_iface"] = json!("awg8");
        Ok(())
    })
    .unwrap();
    let old = nfqws2_awg_profile::read(&db).unwrap();
    std::fs::create_dir_all(tmp.path().join("sys/class/net/awg8")).unwrap();
    assert!(delete(tmp.path(), &db, &f).is_err());
    assert_eq!(nfqws2_awg_profile::read(&db).unwrap(), old);
    assert_eq!(f.0.lock().unwrap().changes, change_count);
}
