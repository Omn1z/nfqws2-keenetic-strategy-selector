use super::*;
use crate::kernel::plan::Target;
use std::fmt::Write;

const BOOT: &str = "01010101-0101-0101-0101-010101010101";
const EMPTY: &str = "*mangle\n:PREROUTING ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A FORWARD -j ACCEPT\nCOMMIT";

#[cfg(target_os = "linux")]
#[test]
fn firmware_snapshot_handles_unterminated_sysctl_values_and_rejects_bad_reads() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("flags/netfilter");
    std::fs::create_dir_all(&dir).unwrap();
    let flag = dir.join("nf_conntrack_fastnat");
    let script = format!(
        "ndmc() {{ echo 'no ppe hardware'; }}\n{}",
        SNAPSHOT
            .replace("/proc/sys/net/", "flags/")
            .replace("/etc/", "etc/")
    );
    let capture = || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .current_dir(root.path())
            .output()
            .unwrap()
    };
    for value in ["0", "0\n"] {
        std::fs::write(&flag, value).unwrap();
        let result = capture();
        assert!(result.status.success());
        assert_eq!(
            result.stdout,
            b"keenetic\nppe hardware off\nnet.netfilter.nf_conntrack_fastnat 0\n"
        );
    }
    for bad in ["", "0 1", "unknown"] {
        std::fs::write(&flag, bad).unwrap();
        assert!(!capture().status.success());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn failed_ip6tables_without_an_ipv6_stack_requires_readable_ipv4_procfs() {
    let dir = tempfile::tempdir().unwrap();
    let script = format!(
        "iptables() {{ :; }}\nip6tables() {{ return 3; }}\n{}",
        ORPHANS.replace("/proc/", "proc/").replace("/opt/", "opt/")
    );
    let capture = || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .current_dir(dir.path())
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(!capture());
    std::fs::create_dir_all(dir.path().join("proc/net")).unwrap();
    std::fs::create_dir_all(dir.path().join("proc/sys/net")).unwrap();
    std::fs::write(dir.path().join("proc/net/route"), "").unwrap();
    assert!(capture());
    std::fs::write(dir.path().join("proc/net/if_inet6"), "").unwrap();
    assert!(!capture());
}

struct Firmware {
    boot: String,
    live: Values,
    hook: Option<Vec<u8>>,
    orphans: bool,
    writable: bool,
    module: bool,
    flushed: usize,
    mutations: Vec<String>,
    tables: [String; 2],
}
struct Router(Mutex<Firmware>);
impl Router {
    fn new(original: &Values) -> Self {
        Self(Mutex::new(Firmware {
            live: original.clone(),
            boot: BOOT.into(),
            hook: None,
            orphans: false,
            writable: true,
            module: true,
            flushed: 0,
            mutations: Vec::new(),
            tables: [EMPTY.into(), EMPTY.into()],
        }))
    }
}
impl Runner for Router {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        let mut f = self.0.lock().unwrap();
        match (program, args) {
            ("cat", ["/proc/sys/kernel/random/boot_id"]) => Ok(f.boot.clone()),
            ("sh", ["-c", SNAPSHOT]) => {
                let mut s = String::from("keenetic\n");
                for (key, on) in &f.live.native {
                    writeln!(s, "ppe {key} {}", if *on { "on" } else { "off" }).unwrap();
                }
                for (key, value) in &f.live.flags {
                    writeln!(s, "{key} {value}").unwrap();
                }
                Ok(s.trim_end().to_owned())
            }
            ("sh", ["-c", s]) if s.contains("echo hook") => Ok(if f.orphans || f.hook.is_some() {
                "hook"
            } else {
                ""
            }
            .into()),
            ("sh", ["-c", s]) if s.contains("device-tree/compatible") => Ok("enabled".into()),
            ("sh", ["-c", _, "awg-accel", cmd]) => {
                let name = cmd.split_ascii_whitespace().last().unwrap();
                assert!(matches!(name, "hardware" | "software"));
                let on = !cmd.starts_with("no ");
                f.live.native.insert(name.into(), on);
                f.mutations.push(cmd.to_string());
                if on && f.module {
                    f.live.flags.entry(FLAGS[5].into()).or_insert(1);
                    f.live.flags.entry(FLAGS[6].into()).or_insert(1);
                }
                Ok(String::new())
            }
            ("sysctl", ["-w", assignment]) => {
                let (key, value) = assignment.split_once('=').unwrap();
                assert!(FLAGS.contains(&key));
                if !f.writable || !f.live.flags.contains_key(key) {
                    return Err(err("unavailable control"));
                }
                f.live.flags.insert(key.into(), value.parse().unwrap());
                f.mutations.push(assignment.to_string());
                Ok(String::new())
            }
            ("sh", ["-c", s]) if s.contains("net.hwnat.ppe_flush") => {
                if !f.module {
                    return Err(err("module unavailable"));
                }
                f.flushed += 1;
                Ok(String::new())
            }
            ("sh", ["-c", s]) if s.contains("net.core.swnat_reset") => Ok(String::new()),
            ("sleep", ["1"]) | ("iptables" | "ip6tables", ["-w", "-t", "mangle", "-S"]) => {
                Ok(String::new())
            }
            ("iptables-save" | "ip6tables-save", []) => {
                Ok(f.tables[usize::from(program.starts_with("ip6"))].clone())
            }
            _ => panic!("unexpected helper {program} {args:?}"),
        }
    }
    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        data: &[u8],
        _: Instant,
    ) -> io::Result<String> {
        let mut f = self.0.lock().unwrap();
        if let ("sh", ["-c", _, "awg-ppe-hook", _, mode]) = (program, args) {
            if f.hook.as_ref().is_some_and(|h| h != data) {
                return Err(err("foreign hook"));
            }
            f.hook = (*mode == "install").then(|| data.to_vec());
            return Ok(String::new());
        }
        assert!(matches!(program, "iptables-restore" | "ip6tables-restore"));
        assert_eq!(args, ["--noflush"]);
        let table = &mut f.tables[usize::from(program.starts_with("ip6"))];
        let mut rows: Vec<String> = table.lines().map(str::to_owned).collect();
        for line in std::str::from_utf8(data).unwrap().lines() {
            let Some((op, rule)) = line.split_once(' ') else {
                continue;
            };
            match op {
                "-N" => {
                    rows.insert(1, format!(":{rule} - [0:0]"));
                }
                "-X" => rows.retain(|l| !l.starts_with(&format!(":{rule} "))),
                "-A" => {
                    let i = rows.iter().position(|l| l == "COMMIT").unwrap();
                    rows.insert(i, line.into());
                }
                "-D" => {
                    let i = rows
                        .iter()
                        .position(|l| l == &format!("-A {rule}"))
                        .unwrap();
                    rows.remove(i);
                }
                "-I" => {
                    let (ch, r) = rule.split_once(" 1 ").unwrap();
                    let i = rows
                        .iter()
                        .position(|l| l.starts_with(&format!("-A {ch} ")) || l == "COMMIT")
                        .unwrap();
                    rows.insert(i, format!("-A {ch} {r}"));
                }
                _ => panic!("unexpected firewall edit"),
            }
        }
        *table = rows.join("\n");
        Ok(String::new())
    }
}
fn active() -> Plan {
    let mut p = Plan::default();
    p.prefixes
        .insert("198.51.100.0/24".parse().unwrap(), "awg2".into());
    p.targets.insert(
        "awg2".into(),
        Target {
            id: "one".into(),
            public_key: String::new(),
            mtu: 1320,
        },
    );
    p
}
fn original(on: bool) -> Values {
    Values {
        native: [("hardware".into(), on), ("software".into(), false)].into(),
        flags: FLAGS[..5]
            .iter()
            .enumerate()
            .map(|(i, k)| (k.to_string(), if on && i % 2 == 0 { 1 } else { 0 }))
            .collect(),
    }
}

#[test]
fn parked_installer_defers_even_eligible_selective_ppe_until_acceptance() {
    const CHILD: &str = "N2S_TEST_PARKED_PPE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kernel::acceleration::tests::parked_installer_defers_even_eligible_selective_ppe_until_acceptance",
            ])
            .env(CHILD, "1")
            .env("N2S_AWG_SELECTIVE_ACCEL", "1")
            .output()
            .unwrap();
        let output = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && output.contains("1 passed"),
            "{output}"
        );
        return;
    }

    use crate::kernel::handoff::parked_guard::{Armed, FILE};
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let run = Router::new(&original(false));
    let k = kernel(&run);
    let plan = active();
    assert!(guards::capable(&k).unwrap());
    db.transaction(|tx| {
        let mut record = begin(&db, tx, &k, &plan)?.unwrap();
        assert!(permitted(&db, &k, &record));
        tx.save_runtime(
            FILE,
            &serde_json::json!({
                "boot": BOOT, "hash": "test", "plan": Plan::default(),
                "policy": {"primary":"one", "reserve":"two", "interfaces":["awg2", "awg3"], "slot":1},
            }),
        )?;
        assert!(Armed::read(&db)?.is_some());
        finish(&db, tx, &k, &mut record, &plan)?;
        assert!(!record.guarded);
        assert!(current(&k)?.matches(&original(false)));
        assert!(run.0.lock().unwrap().mutations.is_empty());
        assert_eq!(record.retry_after, 0);

        tx.delete_runtime(FILE)?;
        finish(&db, tx, &k, &mut record, &plan)?;
        assert!(record.guarded);
        let got = current(&k)?;
        assert!(got.native.values().all(|enabled| *enabled));
        assert_eq!(got.flags[FLAGS[6]], 1);
        restore(&db, tx, &k)?;
        let restored = current(&k)?;
        assert!(restored.matches(&original(false)));
        assert!(restored.flags.values().all(|value| *value == 0));
        Ok(())
    })
    .unwrap();
}

#[test]
fn parked_installer_requires_running_go_restore_preferences_on_keenetic() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let run = Router::new(&original(false));
    let k = kernel(&run);
    assert!(check_parked_handoff(&db, &k, true).is_err());
    assert!(check_parked_handoff(&db, &k, false).is_ok());
    db.transaction(|tx| {
        let mut saved = serde_json::json!({
            "owner":"nfqws2-strategy/awg-acceleration",
            "version":1, "boot_id":BOOT, "sysctls":{},
            "native_ppe":{"hardware":false},
        });
        tx.save(LANDMARK, &saved)?;
        assert!(check_parked_handoff(&db, &k, true).is_err());
        saved["native_ppe"]["software"] = false.into();
        tx.save(LANDMARK, &saved)?;
        check_parked_handoff(&db, &k, true)?;
        saved["native_ppe"]["hardware"] = true.into();
        tx.save(LANDMARK, &saved)?;
        assert!(check_parked_handoff(&db, &k, true).is_err());
        assert!(run.0.lock().unwrap().mutations.is_empty());
        Ok(())
    })
    .unwrap();
}

#[test]
fn restores_exact_same_boot_preferences_after_partial_failure() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let original = original(true);
    let run = Router::new(&original);
    let k = kernel(&run);
    db.transaction(|tx| {
        let r = begin(&db, tx, &k, &active())?.unwrap();
        pause(&k, &r)?;
        assert!(current(&k)?.matches(&original.off()));
        run.0.lock().unwrap().writable = false;
        assert!(restore(&db, tx, &k).is_err());
        assert_eq!(saved(&db)?.unwrap().original, original);
        run.0.lock().unwrap().writable = true;
        restore(&db, tx, &k)?;
        assert!(saved(&db)?.is_none());
        assert!(current(&k)?.matches(&original));
        assert!(run.0.lock().unwrap().hook.is_none());
        Ok(())
    })
    .unwrap();
}
#[test]
fn new_boot_discards_old_preferences_and_leaves_foreign_resources() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let run = Router::new(&original(true));
    let k = kernel(&run);
    db.transaction(|tx| {
        let r = begin(&db, tx, &k, &active())?.unwrap();
        pause(&k, &r)?;
        {
            let mut f = run.0.lock().unwrap();
            f.boot = "02020202-0202-0202-0202-020202020202".into();
            f.live = original(false);
            f.mutations.clear();
        }
        restore(&db, tx, &k)?;
        assert!(run.0.lock().unwrap().mutations.is_empty());
        run.0.lock().unwrap().orphans = true;
        assert!(begin(&db, tx, &k, &active()).is_err());
        assert!(saved(&db)?.is_none());
        run.0.lock().unwrap().orphans = false;
        tx.save(
            LANDMARK,
            &serde_json::json!({"owner":"existing Go process"}),
        )?;
        assert!(begin(&db, tx, &k, &active()).is_err());
        assert!(saved(&db)?.is_none());
        Ok(())
    })
    .unwrap();
}
#[test]
fn protects_both_families_flushes_without_module_unload_and_refuses_foreign_jump() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let run = Router::new(&original(false));
    let k = kernel(&run);
    let ifaces = vec!["awg2".into()];
    db.transaction(|tx| {
        let mut r = begin(&db, tx, &k, &active())?.unwrap();
        assert!(guards::available(&k, &r)?);
        r.guarded = true;
        save(tx, &r)?;
        selective(&k, &r, &ifaces)?;
        assert_eq!(current(&k)?.flags[FLAGS[6]], 1);
        {
            let mut f = run.0.lock().unwrap();
            for table in &f.tables {
                assert_eq!(
                    table
                        .lines()
                        .filter(|l| l.contains("--connbytes 1:32"))
                        .count(),
                    6
                );
                assert_eq!(
                    table
                        .lines()
                        .filter(|l| l.contains("-i awg2") || l.contains("-o awg2"))
                        .count(),
                    4
                );
            }
            f.mutations.clear();
            f.flushed = 0;
        }
        pause(&k, &r)?;
        let f = run.0.lock().unwrap();
        assert_eq!(f.flushed, 1);
        assert!(!f.mutations.iter().any(|cmd| cmd.contains("ppe ")));
        assert!(f.live.native.values().all(|on| *on));
        drop(f);
        let intact = run.0.lock().unwrap().tables[1].clone();
        run.0.lock().unwrap().tables[1]
            .push_str("\n*filter\n-A FORWARD -j NFQUEUE --queue-num 322\nCOMMIT");
        assert!(!guards::intact(&k, &r, &ifaces)?);
        run.0.lock().unwrap().tables[1] =
            intact.replace("COMMIT", &format!("-A FORWARD -j N2RPI_{}\nCOMMIT", r.id));
        assert!(restore(&db, tx, &k).is_err());
        assert!(saved(&db)?.is_some());
        assert!(run.0.lock().unwrap().tables[1].contains(&format!("-A FORWARD -j N2RPI_{}", r.id)));
        run.0.lock().unwrap().tables[1] = intact;
        restore(&db, tx, &k)?;
        let f = run.0.lock().unwrap();
        assert_eq!(f.tables, [EMPTY, EMPTY]);
        assert!(!f.live.native.values().any(|on| *on));
        Ok(())
    })
    .unwrap();
}
#[test]
fn replaced_hook_is_never_removed_and_a_module_failure_can_be_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    let run = Router::new(&original(false));
    let k = kernel(&run);
    db.transaction(|tx| {
        let mut r = begin(&db, tx, &k, &active())?.unwrap();
        r.guarded = true;
        save(tx, &r)?;
        run.0.lock().unwrap().module = false;
        assert!(selective(&k, &r, &["awg2".into()]).is_err());
        conservative(&k)?;
        let original_hook = run
            .0
            .lock()
            .unwrap()
            .hook
            .replace(b"another owner".to_vec());
        assert!(restore(&db, tx, &k).is_err());
        assert_eq!(
            run.0.lock().unwrap().hook.as_deref(),
            Some(&b"another owner"[..])
        );
        assert!(saved(&db)?.is_some());
        run.0.lock().unwrap().hook = original_hook;
        restore(&db, tx, &k)?;
        assert!(saved(&db)?.is_none());
        Ok(())
    })
    .unwrap();
}
