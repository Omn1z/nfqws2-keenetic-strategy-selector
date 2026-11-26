use super::*;
use std::sync::Mutex;

const V4_OLD: &str = "-d 192.0.2.10/32 -p udp -m udp --dport 123 -j ACCEPT";
const V4_BACK: &str = "-s 192.0.2.10/32 -p udp -m udp --sport 123 -j ACCEPT";
const V6_OLD: &str = "-d 2001:db8::10/128 -p udp -m udp --dport 123 -j ACCEPT";
const V6_BACK: &str = "-s 2001:db8::10/128 -p udp -m udp --sport 123 -j ACCEPT";
const STATIC4: &str = "-m set --match-set n2s_nfqb4 dst -j ACCEPT";
const STATIC6: &str = "-d 2001:db8:2::/48 -j ACCEPT";
const OTHER: &str = "-s 192.0.2.30/32 -p udp -m udp --sport 234 -j ACCEPT";
const OLD: &str = "192.0.2.10 123\n2001:db8::10 123\n";
const NEW: &str = "192.0.2.11 321\n2001:db8::11 321\n";

struct Fixture {
    dir: tempfile::TempDir,
    helper: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("tmp")).unwrap();
        let helper = dir.path().join("nfqws-strategy-bypass.sh");
        fs::write(&helper, HELPER).unwrap();
        Self { dir, helper }
    }

    fn request(&self) -> TransportRefresh<'_> {
        TransportRefresh {
            root: self.dir.path(),
            helper: &self.helper,
            old: OLD,
            new: NEW,
            live: true,
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }
}

struct Table {
    rules: Vec<String>,
    active: bool,
    post_only: bool,
}

impl Table {
    fn new(rules: &[&str]) -> Self {
        Self {
            rules: rules.iter().map(|rule| (*rule).into()).collect(),
            active: true,
            post_only: false,
        }
    }

    fn show(&self) -> String {
        if !self.active {
            return "-P INPUT ACCEPT".into();
        }
        if self.post_only {
            return "-N nfqws_post\n-N nfqws2_bypass\n-A nfqws_post -j nfqws2_bypass".into();
        }
        let mut raw = String::from(
            "-N nfqws_post\n-N nfqws_pre\n-N nfqws2_bypass\n-A nfqws_pre -j nfqws2_bypass\n-A nfqws_post -j nfqws2_bypass\n-A nfqws_post -j NFQUEUE",
        );
        for rule in &self.rules {
            write!(raw, "\n-A nfqws2_bypass {rule}").unwrap();
        }
        raw
    }
}

struct Firewall(Mutex<Kernel>);

struct Kernel {
    tables: [Table; 2],
    read_count: usize,
    restore: Vec<String>,
    fail_after_ipv6_commit: bool,
}

impl Firewall {
    fn new() -> Self {
        Self(Mutex::new(Kernel {
            tables: [
                Table::new(&[V4_OLD, STATIC4, V4_BACK, OTHER]),
                Table::new(&[V6_OLD, STATIC6, V6_BACK]),
            ],
            read_count: 0,
            restore: Vec::new(),
            fail_after_ipv6_commit: false,
        }))
    }
}

impl Runner for Firewall {
    fn run(&self, cmd: &str, args: &[&str], _: Instant) -> io::Result<String> {
        assert_eq!(cmd, "sh");
        assert_eq!(&args[..3], &["-c", INSPECT, "n2s-transport-inspect"]);
        let mut kernel = self.0.lock().unwrap();
        kernel.read_count += 1;
        let index = match args[3] {
            "iptables" => 0,
            "ip6tables" => 1,
            _ => panic!("unowned program"),
        };
        Ok(kernel.tables[index].show())
    }

    fn run_input(&self, cmd: &str, args: &[&str], input: &[u8], _: Instant) -> io::Result<String> {
        assert_eq!(args, ["--noflush"]);
        let mut kernel = self.0.lock().unwrap();
        let index = match cmd {
            "iptables-restore" => 0,
            "ip6tables-restore" => 1,
            _ => panic!("unowned program"),
        };
        let batch = std::str::from_utf8(input).unwrap();
        let mut rows = batch
            .strip_prefix("*mangle\n")
            .and_then(|batch| batch.strip_suffix("\nCOMMIT\n"))
            .unwrap()
            .lines();
        let rules = &mut kernel.tables[index].rules;
        for row in &mut rows {
            if let Some(rule) = row.strip_prefix("-D nfqws2_bypass ") {
                let index = rules.iter().position(|current| current == rule).unwrap();
                rules.remove(index);
            } else if let Some((position, rule)) = row
                .strip_prefix("-I nfqws2_bypass ")
                .and_then(|data| data.split_once(' '))
            {
                rules.insert(position.parse::<usize>().unwrap() - 1, rule.into());
            } else {
                panic!("unowned mutation");
            }
        }
        kernel.restore.push(cmd.into());
        if index == 1 && std::mem::take(&mut kernel.fail_after_ipv6_commit) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(String::new())
    }
}

#[test]
fn transport_only_preserves_applied_ipset_and_unrelated_udp() {
    let fixture = Fixture::new();
    let runner = Firewall::new();
    refresh_transport(fixture.request(), &runner, || {
        for family in ["iptables", "ip6tables"] {
            assert!(fixture
                .dir
                .path()
                .join(format!("tmp/nfqws-bypass-{family}.lock"))
                .is_dir());
        }
        let kernel = runner.0.lock().unwrap();
        assert_eq!(
            kernel.tables[0].rules,
            [
                "-d 192.0.2.11 -p udp -m udp --dport 321 -j ACCEPT",
                "-s 192.0.2.11 -p udp -m udp --sport 321 -j ACCEPT",
                STATIC4,
                OTHER,
            ]
        );
        assert_eq!(
            kernel.tables[1].rules,
            [
                "-d 2001:db8::11 -p udp -m udp --dport 321 -j ACCEPT",
                "-s 2001:db8::11 -p udp -m udp --sport 321 -j ACCEPT",
                STATIC6,
            ]
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs::read_dir(fixture.dir.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn reverse_both_families_after_ambiguous_commit_or_publish_error() {
    let fixture = Fixture::new();
    for fail_after_commit in [true, false] {
        let runner = Firewall::new();
        runner.0.lock().unwrap().fail_after_ipv6_commit = fail_after_commit;
        let error = refresh_transport(fixture.request(), &runner, || {
            assert!(!fail_after_commit);
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();
        assert_eq!(
            error.kind(),
            if fail_after_commit {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::PermissionDenied
            }
        );
        let kernel = runner.0.lock().unwrap();
        assert_eq!(kernel.tables[0].rules, [V4_OLD, STATIC4, V4_BACK, OTHER]);
        assert_eq!(kernel.tables[1].rules, [V6_OLD, STATIC6, V6_BACK]);
        assert_eq!(
            kernel.restore,
            [
                "iptables-restore",
                "ip6tables-restore",
                "ip6tables-restore",
                "iptables-restore"
            ]
        );
    }
}

#[test]
fn manual_off_never_opens_the_firewall_and_missing_ipv6_is_valid() {
    let fixture = Fixture::new();
    let runner = Firewall::new();
    let mut request = fixture.request();
    request.live = false;
    refresh_transport(request, &runner, || {
        assert_eq!(runner.0.lock().unwrap().read_count, 0);
        Ok(())
    })
    .unwrap();
    runner.0.lock().unwrap().tables[1].active = false;
    refresh_transport(fixture.request(), &runner, || {
        assert_eq!(runner.0.lock().unwrap().restore, ["iptables-restore"]);
        Ok(())
    })
    .unwrap();
}

#[test]
fn verifies_both_families_and_exact_helper_before_any_mutation() {
    let fixture = Fixture::new();
    let runner = Firewall::new();
    runner.0.lock().unwrap().tables[1].post_only = true;
    assert!(
        refresh_transport(fixture.request(), &runner, || panic!("unexpected publish")).is_err()
    );
    assert!(runner.0.lock().unwrap().restore.is_empty());
    let table = Table::new(&[V4_OLD, V4_BACK]).show();
    let foreign = format!(
        "{table}\n-A OUTPUT -m comment --comment \"send -j FORWARD first\" -j nfqws2_bypass"
    );
    assert!(Snapshot::parse(&foreign, Family::V4).is_err());
    let runner = Firewall::new();
    fs::write(&fixture.helper, format!("{HELPER}\n# external edit")).unwrap();
    assert!(
        refresh_transport(fixture.request(), &runner, || panic!("unexpected publish")).is_err()
    );
    assert_eq!(runner.0.lock().unwrap().read_count, 0);
}

#[test]
fn tolerates_complete_installed_pairs_when_manifest_and_firewall_lag() {
    let fixture = Fixture::new();
    let runner = Firewall::new();
    let next4 = [
        "-d 192.0.2.11/32 -p udp -m udp --dport 321 -j ACCEPT",
        "-s 192.0.2.11/32 -p udp -m udp --sport 321 -j ACCEPT",
        STATIC4,
    ];
    runner.0.lock().unwrap().tables[0] = Table::new(&next4);
    runner.0.lock().unwrap().tables[1].rules = vec![STATIC6.into()];
    refresh_transport(fixture.request(), &runner, || {
        let kernel = runner.0.lock().unwrap();
        assert_eq!(kernel.tables[0].rules, next4);
        assert_eq!(kernel.restore, ["ip6tables-restore"]);
        Ok(())
    })
    .unwrap();
    runner.0.lock().unwrap().tables[0].rules.remove(0);
    assert!(
        refresh_transport(fixture.request(), &runner, || panic!("unexpected publish")).is_err()
    );
    assert_eq!(runner.0.lock().unwrap().restore, ["ip6tables-restore"]);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires iptables and permission to create a private network namespace"]
fn real_xtables_transport_restore() {
    use nfqws2_router_command::System;
    use std::process::Command;

    const NS_PARENT: &str = "N2S_TRANSPORT_TEST_PARENT_NETNS";
    let current_ns = fs::read_link("/proc/self/ns/net").unwrap();
    let Some(parent_ns) = std::env::var_os(NS_PARENT) else {
        let module = module_path!().split_once("::").unwrap().1;
        let name = format!("{module}::real_xtables_transport_restore");
        let output = Command::new("unshare")
            .args(["-n", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", &name, "--nocapture"])
            .env(NS_PARENT, current_ns.as_os_str())
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && log.contains("1 passed"),
            "{log}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    // Both checks precede any command. The live namespace (including its
    // tables) is discarded as soon as the isolated child exits.
    assert_ne!(current_ns.as_os_str(), parent_ns);
    assert_ne!(current_ns, fs::read_link("/proc/1/ns/net").unwrap());

    let fixture = Fixture::new();
    let request = || TransportRefresh {
        deadline: Instant::now() + Duration::from_secs(30),
        ..fixture.request()
    };
    for (family, [first, static_rule, last]) in [
        (Family::V4, [V4_OLD, "-d 192.0.2.0/26 -j ACCEPT", V4_BACK]),
        (Family::V6, [V6_OLD, STATIC6, V6_BACK]),
    ] {
        let batch = format!(
            "*mangle\n:nfqws_post - [0:0]\n:nfqws_pre - [0:0]\n:nfqws2_bypass - [0:0]\n-A nfqws_post -j nfqws2_bypass\n-A nfqws_pre -j nfqws2_bypass\n-A nfqws2_bypass {first}\n-A nfqws2_bypass {static_rule}\n-A nfqws2_bypass {last}\nCOMMIT\n",
        );
        System
            .run_input(
                family.restore(),
                &["--noflush"],
                batch.as_bytes(),
                request().deadline,
            )
            .unwrap();
    }
    let tables = |deadline| {
        [Family::V4, Family::V6].map(|family| {
            Snapshot::inspect(&System, family, fixture.dir.path(), deadline)
                .unwrap()
                .unwrap()
        })
    };
    let before = tables(request().deadline);
    let error = refresh_transport(request(), &System, || {
        Err(io::ErrorKind::PermissionDenied.into())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(before, tables(request().deadline));
    refresh_transport(request(), &System, || Ok(())).unwrap();
    for (actual, prior) in tables(request().deadline).iter().zip(&before) {
        assert_ne!(actual.pairs(), prior.pairs());
        assert_eq!(actual.0.len(), prior.0.len());
        assert_eq!(actual.0[2], prior.0[1]);
    }
}
