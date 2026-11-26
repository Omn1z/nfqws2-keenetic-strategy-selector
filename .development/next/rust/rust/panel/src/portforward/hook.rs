use super::*;
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
const CLEANUP: &str = include_str!("cleanup.sh");
#[cfg(any(target_os = "linux", test))]
fn render(
    ifaces: &[String],
    rules: &[Rule],
    helper: &Path,
    conf: &str,
) -> io::Result<Option<String>> {
    use std::fmt::Write;
    if rules.iter().all(|r| !r.enabled) {
        return Ok(None);
    }
    let mut script = String::from(include_str!("setup.sh"));
    let mut wan = Vec::new();
    for name in ifaces.iter().map(|v| v.trim()) {
        if wan::literal(name) && !wan.contains(&name) {
            wan.push(name);
        }
    }
    let automatic = wan.is_empty();
    let mut inputs: Vec<_> = wan.into_iter().map(|name| format!("'{name}'")).collect();
    if automatic {
        let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        if ifaces.iter().any(|s| !wan::wildcard(s.trim())) {
            return Err(invalid("no valid WAN selector for port forwarding"));
        }
        // setup.sh already cleared both owned chains. A missing or older
        // helper leaves them empty until the next firmware firewall event.
        write!(
            script,
            "set -f\nwan=$({} port-forward-wan {}",
            quote(
                helper
                    .to_str()
                    .ok_or_else(|| invalid("invalid panel path"))?
            ),
            quote(conf)
        )
        .unwrap();
        for pattern in ifaces {
            write!(script, " {}", quote(pattern.trim())).unwrap();
        }
        script.push_str(") || exit 0\nfor iface in $wan; do\ncase \"$iface\" in *[!a-zA-Z0-9_.-]*) exit 0;; esac\ndone\nfor iface in $wan; do\n");
        inputs.push("\"$iface\"".into());
    }
    for rule in rules.iter().filter(|r| r.enabled) {
        let ip = rule
            .device_ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| invalid("invalid LAN address"))?;
        for (proto, ports) in [("tcp", &rule.tcp), ("udp", &rule.udp)] {
            for r in ports {
                let port = if r.start == r.end {
                    r.start.to_string()
                } else {
                    format!("{}:{}", r.start, r.end)
                };
                for iface in &inputs {
                    writeln!(script,"iptables -t nat -A N2S_PFWD -i {iface} -p {proto} --dport {port} -j DNAT --to-destination {ip}").unwrap();
                    writeln!(script,"iptables -A N2S_PFWD_FWD -i {iface} -p {proto} -d {ip} --dport {port} -j ACCEPT").unwrap();
                }
            }
        }
    }
    if automatic {
        script.push_str("done\n");
    }
    Ok(Some(script))
}
#[cfg(target_os = "linux")]
pub(super) fn apply(path: &Path, cfg: &nfqws2_config::Config, rules: &[Rule]) -> io::Result<()> {
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use tempfile::NamedTempFile;
    let dir = path
        .parent()
        .ok_or_else(|| invalid("missing hook directory"))?;
    let mut cmd = Command::new("sh");
    let mut hook = None;
    let panel = nfqws2_config::Resolver::current().path(nfqws2_config::Key::StrategyBin);
    if let Some(script) = render(&cfg.wan_ifaces, rules, panel, &cfg.nfqws2_conf)? {
        fs::create_dir_all(dir)?;
        let mut file = NamedTempFile::new_in(dir)?;
        file.write_all(script.as_bytes())?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
        file.as_file().sync_all()?;
        // Close the write handle before asking the shell to execute the file.
        let temp = file.into_temp_path();
        cmd.arg(&temp);
        hook = Some(temp);
    } else {
        cmd.args(["-c", CLEANUP]);
    }
    let mut child = cmd.stdin(Stdio::null()).spawn()?;
    let now = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(io::Error::other(format!("firewall hook exited {status}")));
            }
            break;
        }
        if now.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "firewall hook timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
    if let Some(f) = hook {
        f.persist(path)?;
    } else if let Err(e) = fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    if dir.exists() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub(super) fn apply(_: &Path, _: &nfqws2_config::Config, _: &[Rule]) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hook_uses_only_managed_chains_ports_and_interface_names() {
        let rule = Rule {
            preset_id: "delta-force".into(),
            profile_id: "pc".into(),
            device_ip: "192.168.1.7".into(),
            enabled: true,
            name: "x\nwhoami".into(),
            ..Rule::default()
        }
        .normalize()
        .unwrap();
        let script = render(
            &["bad;reboot".into(), "eth2".into(), "eth2".into()],
            &[rule],
            Path::new("/test/n2s"),
            "/etc/nfqws2.conf",
        )
        .unwrap()
        .unwrap();
        assert_eq!(script.matches("--dport 3568:3569").count(), 2);
        assert!(!script.contains("reboot") && !script.contains("whoami"));
        assert!(script.contains("-i 'eth2'"));
        assert!(CLEANUP.contains("-X N2S_PFWD"));
        assert!(render(&[], &[], Path::new("/test/n2s"), "/etc/nfqws2.conf")
            .unwrap()
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restored_go_rule_rechecks_wan_on_hook_replay_and_clears_after_downgrade() {
        use std::{fs, os::unix::fs::PermissionsExt, process::Command};
        let dir = tempfile::tempdir().unwrap();
        let program = |name: &str, contents: &str| {
            let path = dir.path().join(name);
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        program("iptables", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> called\ncase \" $* \" in *' -D '*) exit 1;; esac\n");
        let helper = program("test panel's n2s", "#!/bin/sh\n[ \"$1\" = port-forward-wan ] && [ \"$2\" = \"/etc/isp's conf\" ] && [ \"$3\" = 'ppp+' ] || exit 1\nread -r wan < current\nprintf '%s\\n' \"$wan\"\n");
        let saved: Saved = serde_json::from_value(serde_json::json!({"rules":[{
            "id":"go-pc","name":"PC","profile_id":"pc","preset_id":"delta-force",
            "enabled":true,"device_ip":"192.168.10.5","device_iface":"br0",
            "tcp":null,"udp":[{"start":9,"end":9}],"created_at":17,"updated_at":31
        }]}))
        .unwrap();
        let rule = saved.rules.unwrap().remove(0).normalize().unwrap();
        assert_eq!(
            (rule.created_at, rule.updated_at, rule.device_iface.as_str()),
            (17, 31, "br0")
        );
        let hook = program(
            "hook",
            &render(&["ppp+".into()], &[rule], &helper, "/etc/isp's conf")
                .unwrap()
                .unwrap(),
        );
        let replay = || {
            let log = dir.path().join("called");
            fs::write(&log, "").unwrap();
            assert!(Command::new("/bin/sh")
                .arg(&hook)
                .current_dir(dir.path())
                .env_clear()
                .env("PATH", dir.path())
                .status()
                .unwrap()
                .success());
            fs::read_to_string(log).unwrap()
        };
        for link in ["ppp0", "ppp1"] {
            fs::write(dir.path().join("current"), format!("{link}\n")).unwrap();
            let called = replay();
            let rules = called
                .lines()
                .filter(|s| s.contains("--dport"))
                .collect::<Vec<_>>();
            assert_eq!(rules, [
                format!("-t nat -A N2S_PFWD -i {link} -p udp --dport 3568:3569 -j DNAT --to-destination 192.168.10.5"),
                format!("-A N2S_PFWD_FWD -i {link} -p udp -d 192.168.10.5 --dport 3568:3569 -j ACCEPT")
            ]);
        }
        // Missing binary during rollback and an older CLI without this
        // command both leave the hook dormant after removing any old rules.
        for missing in [false, true] {
            if missing {
                fs::remove_file(&helper).unwrap();
            } else {
                fs::write(&helper, "#!/bin/sh\nexit 2\n").unwrap();
            }
            let called = replay();
            assert!(
                called.contains("-t nat -F N2S_PFWD\n") && called.contains("-F N2S_PFWD_FWD\n")
            );
            assert!(!called.contains("--dport") && !called.contains("-F FORWARD"));
        }
    }
}
