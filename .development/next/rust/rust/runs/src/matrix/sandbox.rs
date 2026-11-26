//! A test slot owns its child, queue and exact firewall rules. It never flushes
//! existing chains, and removes the marking jump before dismantling isolation.
use nfqws2_router_command::{Runner, System};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    fs, io,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const PROC_MARK: &str = "0x40000000/0x40000000";
const EXCLUDE_MARK: &str = "0x20000000/0x20000000";
const QUEUES: &str = "/proc/net/netfilter/nfnetlink_queue";
const SLOT_PREFIX: &str = "n2s-matrix-slot-";

#[derive(Clone, Deserialize)]
pub(super) struct Config {
    pub nfqws_bin: String,
    pub wan_ifaces: Vec<String>,
    pub base_args: Option<Vec<String>>,
    pub first_queue: i32,
    pub main_queue: i32,
    pub port_base: i32,
    pub ports_per_worker: i32,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn slot_directory(root: &std::path::Path) -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(SLOT_PREFIX);
    // Recovery only trusts directories private to the running uid. Set
    // their permissions at creation, independently of the service's umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(root)
}

#[derive(Clone, Deserialize, Serialize)]
struct Rule {
    chain: String,
    args: Vec<String>,
}

pub(super) struct Sandbox {
    config: Config,
    queue: u16,
    ports: (u16, u16),
    next_probe_port: Cell<u16>,
    chains: [String; 3], // post, pre, output
    tag: String,
    created: Vec<String>,
    rules: Vec<Rule>,
    main_chains: Vec<String>,
    local_ips: Vec<String>,
    work: Option<tempfile::TempDir>,
    child: Option<Child>,
    queued: bool,
    runner: Arc<dyn Runner>,
    cleanup_deadline: Option<Instant>,
}

#[derive(Deserialize, Serialize)]
struct Journal {
    tag: String,
    created: Vec<String>,
    rules: Vec<Rule>,
}

fn parameters(config: &Config, worker: usize) -> io::Result<(u16, (u16, u16))> {
    let worker = i64::try_from(worker).map_err(|_| invalid("invalid worker number"))?;
    let queue = i64::from(config.first_queue)
        .checked_add(worker)
        .ok_or_else(|| invalid("invalid queue number"))?;
    let lo = worker
        .checked_mul(i64::from(config.ports_per_worker))
        .and_then(|offset| i64::from(config.port_base).checked_add(offset))
        .ok_or_else(|| invalid("invalid source-port range"))?;
    let hi = lo
        .checked_add(i64::from(config.ports_per_worker) - 1)
        .ok_or_else(|| invalid("invalid source-port range"))?;
    if !(0..=65535).contains(&queue)
        || queue == i64::from(config.main_queue)
        || config.ports_per_worker < 1
        || lo < 1
        || hi > 65535
        || hi < lo
        || config.wan_ifaces.is_empty()
        || config.wan_ifaces.iter().any(|name| {
            name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-.@:".contains(&c))
        })
    {
        return Err(invalid(
            "invalid sandbox queue, WAN interfaces or source-port range",
        ));
    }
    Ok((queue as u16, (lo as u16, hi as u16)))
}

pub(super) fn reserved_ports(
    config: &Config,
    last_slot: usize,
) -> io::Result<std::ops::RangeInclusive<u16>> {
    let (_, (first, _)) = parameters(config, 0)?;
    let (_, (_, last)) = parameters(config, last_slot)?;
    Ok(first..=last)
}

impl Sandbox {
    pub(super) fn new(config: &Config, worker: usize) -> io::Result<Self> {
        Self::open(config, worker, true)
    }

    pub(super) fn new_baseline(config: &Config, worker: usize) -> io::Result<Self> {
        Self::open(config, worker, false)
    }

    fn open(config: &Config, worker: usize, queued: bool) -> io::Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "isolated strategy tests require Linux and iptables",
            ));
        }
        let (queue, ports) = parameters(config, worker)?;
        let queues = read_queues()?;
        if queue_row(&queues, queue)?.is_some() {
            return Err(invalid("sandbox NFQUEUE is already bound"));
        }
        check_ports(&fs::read_to_string("/proc/net/tcp")?, ports)?;
        match fs::read_to_string("/proc/net/tcp6") {
            Ok(sockets) => check_ports(&sockets, ports)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let tag = format!("N2SM_{}", nfqws2_store::new_id()?);
        let mut sandbox = Self {
            config: config.clone(),
            queue,
            ports,
            next_probe_port: Cell::new(ports.0),
            chains: [format!("{tag}_P"), format!("{tag}_R"), format!("{tag}_O")],
            tag,
            created: Vec::new(),
            rules: Vec::new(),
            main_chains: Vec::new(),
            local_ips: local_ipv4()?,
            work: Some(slot_directory(&std::env::temp_dir())?),
            child: None,
            queued,
            runner: Arc::new(System),
            cleanup_deadline: None,
        };
        if let Err(error) = sandbox.install() {
            return match sandbox.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::other(format!("{error}; cleanup: {cleanup}"))),
            };
        }
        Ok(sandbox)
    }

    fn ipt(&self, args: &[String]) -> io::Result<String> {
        ipt(
            self.runner.as_ref(),
            args,
            self.cleanup_deadline
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(4)),
        )
    }

    fn journal(&self) -> io::Result<()> {
        write_journal(
            self.work.as_ref().unwrap().path(),
            &Journal {
                tag: self.tag.clone(),
                created: self.created.clone(),
                rules: self.rules.clone(),
            },
        )
    }

    fn add(&mut self, chain: &str, first: bool, args: Vec<String>) -> io::Result<()> {
        let mut command = strings(&["-t", "mangle", if first { "-I" } else { "-A" }, chain]);
        if first {
            command.push("1".into());
        }
        command.extend(args.iter().cloned());
        // Record intent before the mutation: a killed helper can leave an
        // installed rule even if it never receives the command's exit status.
        self.rules.push(Rule {
            chain: chain.into(),
            args,
        });
        self.journal()?;
        self.ipt(&command)?;
        Ok(())
    }

    fn main_snapshot(&self) -> io::Result<Vec<String>> {
        let rules = self.ipt(&strings(&["-t", "mangle", "-S"]))?;
        Ok(["nfqws_post", "nfqws_pre"]
            .into_iter()
            .filter(|name| {
                rules
                    .lines()
                    .any(|line| line.trim() == format!("-N {name}"))
            })
            .map(str::to_owned)
            .collect())
    }

    fn install(&mut self) -> io::Result<()> {
        self.main_chains = self.main_snapshot()?;
        for chain in self.chains.clone() {
            self.created.push(chain.clone());
            self.journal()?;
            self.ipt(&strings(&["-t", "mangle", "-N", &chain]))?;
        }
        let [post, pre, output] = self.chains.clone();
        let sport = format!("{}:{}", self.ports.0, self.ports.1);
        for chain in [&output, &post] {
            self.add(
                chain,
                false,
                strings(&["-m", "mark", "--mark", PROC_MARK, "-j", "RETURN"]),
            )?;
        }
        self.add(
            &output,
            false,
            strings(&[
                "-p",
                "tcp",
                "--dport",
                "443",
                "--sport",
                &sport,
                "-j",
                "CONNMARK",
                "--set-xmark",
                EXCLUDE_MARK,
            ]),
        )?;
        if self.queued {
            for iface in self.config.wan_ifaces.clone() {
                for source in self.local_ips.clone() {
                    self.add(
                        &post,
                        false,
                        queue_rule(&iface, &source, &sport, self.queue, false),
                    )?;
                    self.add(
                        &pre,
                        false,
                        queue_rule(&iface, &source, &sport, self.queue, true),
                    )?;
                }
            }
        }
        for chain in self.main_chains.clone() {
            for source in self.local_ips.clone() {
                self.add(&chain, true, main_guard(&chain, &source, &sport, &self.tag))?;
            }
        }
        self.add("POSTROUTING", true, strings(&["-j", &post]))?;
        self.add("PREROUTING", true, strings(&["-j", &pre]))?;
        // Marking is enabled only once both main-service exclusions and the
        // candidate's packet paths are installed.
        self.add("OUTPUT", true, strings(&["-j", &output]))?;
        Ok(())
    }

    pub(super) fn port_range(&self) -> (u16, u16) {
        self.ports
    }

    pub(super) fn local_ipv4_addresses(&self) -> &[String] {
        &self.local_ips
    }

    pub(super) fn next_probe_port(&self) -> u16 {
        let port = self.next_probe_port.get();
        let next = if port == self.ports.1 {
            self.ports.0
        } else {
            port + 1
        };
        self.next_probe_port.set(next);
        port
    }

    fn check_rules(&self) -> io::Result<()> {
        if self.rules.is_empty()
            || local_ipv4()? != self.local_ips
            || self.main_snapshot()? != self.main_chains
        {
            return Err(invalid("sandbox isolation changed; repeat the test"));
        }
        for rule in &self.rules {
            let mut args = strings(&["-t", "mangle", "-C", &rule.chain]);
            args.extend(rule.args.iter().cloned());
            self.ipt(&args)
                .map_err(|_| invalid("sandbox firewall rule was lost; repeat the test"))?;
        }
        Ok(())
    }

    pub(super) fn check(&mut self) -> io::Result<()> {
        self.check_rules()?;
        if self.queued {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| invalid("candidate engine is not running"))?;
            if child.try_wait()?.is_some() {
                return Err(invalid("candidate engine exited during measurement"));
            }
            self.packets()?;
        }
        Ok(())
    }

    pub(super) fn start(&mut self, args: &str, cancel: &AtomicBool) -> io::Result<()> {
        self.stop();
        if !self.queued {
            return Err(invalid("baseline slot cannot start a candidate"));
        }
        self.check_rules()?;
        if queue_row(&read_queues()?, self.queue)?.is_some() {
            return Err(invalid("sandbox NFQUEUE is already bound"));
        }
        let argv = engine_args(
            &self.config,
            self.queue,
            self.work.as_ref().unwrap().path(),
            args,
        )?;
        let mut command = Command::new(&self.config.nfqws_bin);
        command
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tied_to_parent(&mut command);
        self.child = Some(command.spawn()?);
        let end = Instant::now() + Duration::from_secs(10);
        let result = loop {
            if cancel.load(Ordering::Acquire) {
                break Err(io::ErrorKind::Interrupted.into());
            }
            if self.child.as_mut().unwrap().try_wait()?.is_some() {
                break Err(invalid(
                    "candidate engine exited before binding its NFQUEUE",
                ));
            }
            match self.packets() {
                Ok(_) => break Ok(()),
                Err(e) if e.kind() != io::ErrorKind::NotFound => break Err(e),
                Err(_) => (),
            }
            if Instant::now() >= end {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "candidate NFQUEUE did not become ready",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        };
        if result.is_err() {
            self.stop();
        }
        result
    }

    pub(super) fn packets(&self) -> io::Result<u32> {
        let (peer, sequence) = queue_row(&read_queues()?, self.queue)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "candidate NFQUEUE is not bound")
        })?;
        if self.child.as_ref().is_none_or(|child| child.id() != peer) {
            return Err(invalid("candidate NFQUEUE belongs to another process"));
        }
        Ok(sequence)
    }

    pub(super) fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // A foreground child is directly owned by this slot. SIGKILL also
            // avoids unbounded teardown when an external engine hangs.
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        self.stop();
        self.cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(18));
        while let Some(rule) = self.rules.last() {
            let mut args = strings(&["-t", "mangle", "-D", &rule.chain]);
            args.extend(rule.args.iter().cloned());
            if self.ipt(&args).is_err() {
                // An external firewall reload can remove an owned rule. Only
                // accept its absence after a successful table inspection;
                // permission and backend errors must remain visible.
                args[2] = "-C".into();
                self.ipt(&strings(&["-t", "mangle", "-S"]))?;
                if self.ipt(&args).is_ok() {
                    return Err(io::Error::other("could not remove sandbox firewall rule"));
                }
            }
            self.rules.pop();
            self.journal()?;
        }
        while let Some(chain) = self.created.last() {
            if self.ipt(&strings(&["-t", "mangle", "-X", chain])).is_err() {
                let table = self.ipt(&strings(&["-t", "mangle", "-S"]))?;
                if table
                    .lines()
                    .any(|line| line.trim() == format!("-N {chain}"))
                {
                    return Err(io::Error::other("could not remove sandbox firewall chain"));
                }
            }
            self.created.pop();
            self.journal()?;
        }
        Ok(())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            // A later helper recovers these exact rules under the matrix lock.
            if let Some(work) = self.work.take() {
                let _ = work.keep();
            }
        }
    }
}

fn ipt(runner: &dyn Runner, args: &[String], deadline: Instant) -> io::Result<String> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let mut refs = vec!["-w", "2"];
    refs.extend(args.iter().map(String::as_str));
    runner.run(
        "iptables",
        &refs,
        deadline.min(Instant::now() + Duration::from_secs(4)),
    )
}

fn write_journal(dir: &std::path::Path, journal: &Journal) -> io::Result<()> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer(&mut file, journal)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(dir.join("owned-rules.json"))
        .map_err(|e| e.error)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn tied_to_parent(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn tied_to_parent(_: &mut Command) {}

/// The caller holds the global matrix lock, including during panel startup.
/// A dead helper's journal names only its random chains and exact vendor guards.
pub(super) fn recover() -> io::Result<()> {
    recover_at(&std::env::temp_dir(), &System)
}

fn recover_at(root: &std::path::Path, runner: &dyn Runner) -> io::Result<()> {
    use std::io::Read;
    let deadline = Instant::now() + Duration::from_secs(18);
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(SLOT_PREFIX) {
            continue;
        }
        let dir = entry.path();
        let meta = fs::symlink_metadata(&dir)?;
        if !meta.is_dir() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                continue;
            }
        }
        let file = dir.join("owned-rules.json");
        let mut raw = Vec::new();
        match fs::File::open(&file) {
            Ok(input) => {
                input.take((256 << 10) + 1).read_to_end(&mut raw)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
        if raw.len() > 256 << 10 {
            return Err(invalid("oversized sandbox ownership journal"));
        }
        let mut journal: Journal = serde_json::from_slice(&raw)?;
        validate_journal(&journal)?;
        while let Some(rule) = journal.rules.last() {
            let mut args = strings(&["-t", "mangle", "-D", &rule.chain]);
            args.extend(rule.args.iter().cloned());
            if ipt(runner, &args, deadline).is_err() {
                ipt(runner, &strings(&["-t", "mangle", "-S"]), deadline)?;
                args[2] = "-C".into();
                if ipt(runner, &args, deadline).is_ok() {
                    return Err(io::Error::other("could not recover sandbox firewall rule"));
                }
            }
            journal.rules.pop();
            write_journal(&dir, &journal)?;
        }
        while let Some(chain) = journal.created.last() {
            if ipt(runner, &strings(&["-t", "mangle", "-X", chain]), deadline).is_err() {
                let table = ipt(runner, &strings(&["-t", "mangle", "-S"]), deadline)?;
                if table
                    .lines()
                    .any(|line| line.trim() == format!("-N {chain}"))
                {
                    return Err(io::Error::other("could not recover sandbox firewall chain"));
                }
            }
            journal.created.pop();
            write_journal(&dir, &journal)?;
        }
        // read_dir gave a direct child of the temporary directory; symlinks
        // were rejected and the owner/mode and journal were checked above.
        fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

fn validate_journal(journal: &Journal) -> io::Result<()> {
    let Some(id) = journal.tag.strip_prefix("N2SM_") else {
        return Err(invalid("invalid sandbox journal tag"));
    };
    if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid sandbox journal tag"));
    }
    let post = format!("{}_P", journal.tag);
    let pre = format!("{}_R", journal.tag);
    let out = format!("{}_O", journal.tag);
    let owned = [&post, &pre, &out];
    if journal.created.len() > 3
        || journal.rules.len() > 1024
        || journal.created.iter().any(|chain| !owned.contains(&chain))
    {
        return Err(invalid("invalid sandbox journal chains"));
    }
    for rule in &journal.rules {
        if owned.contains(&&rule.chain) {
            if valid_owned_rule(rule, &post, &pre, &out) {
                continue;
            }
            return Err(invalid("invalid sandbox journal private rule"));
        }
        let expected = match rule.chain.as_str() {
            "POSTROUTING" => Some(&post),
            "PREROUTING" => Some(&pre),
            "OUTPUT" => Some(&out),
            _ => None,
        };
        if let Some(chain) = expected {
            if rule.args == strings(&["-j", chain]) {
                continue;
            }
            return Err(invalid("invalid sandbox journal jump"));
        }
        if !matches!(rule.chain.as_str(), "nfqws_post" | "nfqws_pre") {
            return Err(invalid("invalid sandbox journal rule owner"));
        }
        let value = |key| {
            rule.args
                .windows(2)
                .find(|pair| pair[0] == key)
                .map(|pair| pair[1].as_str())
        };
        let source =
            value("--ctorigsrc").ok_or_else(|| invalid("missing sandbox journal source"))?;
        let ip: std::net::Ipv4Addr = source
            .parse()
            .map_err(|_| invalid("invalid sandbox journal source"))?;
        let sport = value(if rule.chain == "nfqws_post" {
            "--sport"
        } else {
            "--dport"
        })
        .ok_or_else(|| invalid("missing sandbox journal ports"))?;
        let ports = sport
            .split_once(':')
            .and_then(|(a, b)| Some((a.parse::<u16>().ok()?, b.parse::<u16>().ok()?)));
        if ip.is_unspecified()
            || !ports.is_some_and(|(lo, hi)| lo > 0 && hi >= lo)
            || rule.args != main_guard(&rule.chain, source, sport, &journal.tag)
        {
            return Err(invalid("invalid sandbox journal guard"));
        }
    }
    Ok(())
}

fn valid_owned_rule(rule: &Rule, post: &str, pre: &str, out: &str) -> bool {
    if (rule.chain == post || rule.chain == out)
        && rule.args == strings(&["-m", "mark", "--mark", PROC_MARK, "-j", "RETURN"])
    {
        return true;
    }
    let value = |key| {
        rule.args
            .windows(2)
            .find(|pair| pair[0] == key)
            .map(|pair| pair[1].as_str())
    };
    let reply = rule.chain == pre;
    let Some(sport) = value(if reply { "--dport" } else { "--sport" }) else {
        return false;
    };
    let Some((lo, hi)) = sport
        .split_once(':')
        .and_then(|(a, b)| Some((a.parse::<u16>().ok()?, b.parse::<u16>().ok()?)))
    else {
        return false;
    };
    if lo == 0 || hi < lo {
        return false;
    }
    if rule.chain == out {
        return rule.args
            == strings(&[
                "-p",
                "tcp",
                "--dport",
                "443",
                "--sport",
                sport,
                "-j",
                "CONNMARK",
                "--set-xmark",
                EXCLUDE_MARK,
            ]);
    }
    let Some(iface) = value(if reply { "-i" } else { "-o" }) else {
        return false;
    };
    let Some(source) = value("--ctorigsrc") else {
        return false;
    };
    let Some(queue) = value("--queue-num").and_then(|s| s.parse::<u16>().ok()) else {
        return false;
    };
    if source.parse::<std::net::Ipv4Addr>().is_err()
        || iface.is_empty()
        || iface.len() > 15
        || !iface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.@:".contains(&c))
    {
        return false;
    }
    rule.args == queue_rule(iface, source, sport, queue, reply)
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|v| (*v).to_owned()).collect()
}

fn queue_rule(iface: &str, source: &str, sport: &str, queue: u16, reply: bool) -> Vec<String> {
    strings(&[
        if reply { "-i" } else { "-o" },
        iface,
        "-p",
        "tcp",
        "--sport",
        if reply { "443" } else { sport },
        "--dport",
        if reply { sport } else { "443" },
        "-m",
        "connmark",
        "--mark",
        EXCLUDE_MARK,
        "-m",
        "conntrack",
        "--ctorigsrc",
        source,
        "-m",
        "connbytes",
        "--connbytes",
        "1:16",
        "--connbytes-mode",
        "packets",
        "--connbytes-dir",
        if reply { "reply" } else { "original" },
        "-j",
        "NFQUEUE",
        "--queue-num",
        &queue.to_string(),
        "--queue-bypass",
    ])
}

fn main_guard(chain: &str, source: &str, sport: &str, tag: &str) -> Vec<String> {
    strings(&[
        "-p",
        "tcp",
        "--sport",
        if chain == "nfqws_post" { sport } else { "443" },
        "--dport",
        if chain == "nfqws_post" { "443" } else { sport },
        "-m",
        "connmark",
        "--mark",
        EXCLUDE_MARK,
        "-m",
        "conntrack",
        "--ctorigsrc",
        source,
        "-m",
        "comment",
        "--comment",
        tag,
        "-j",
        "RETURN",
    ])
}

fn engine_args(
    config: &Config,
    queue: u16,
    work: &std::path::Path,
    strategy: &str,
) -> io::Result<Vec<String>> {
    let mut args = vec![
        format!("--qnum={queue}"),
        format!("--writable={}", work.display()),
    ];
    for arg in config
        .base_args
        .iter()
        .flatten()
        .map(String::as_str)
        .chain(strategy.split_whitespace())
    {
        let key = arg.split('=').next().unwrap_or("");
        if matches!(key, "--daemon" | "-D") {
            continue;
        }
        let ownership = [
            "--qnum",
            "--daemon",
            "--pidfile",
            "--writable",
            "--new",
            "--user",
            "--uid",
        ];
        if (key.starts_with("--") && ownership.iter().any(|option| option.starts_with(key)))
            || arg.starts_with("-q")
            || arg.starts_with("-D")
            || arg.contains('\0')
        {
            return Err(invalid("candidate arguments override sandbox ownership"));
        }
        args.push(arg.into());
    }
    Ok(args)
}

fn read_queues() -> io::Result<String> {
    match fs::read_to_string(QUEUES) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

fn queue_row(text: &str, queue: u16) -> io::Result<Option<(u32, u32)>> {
    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first().and_then(|s| s.parse::<u16>().ok()) != Some(queue) {
            continue;
        }
        if found.is_some() || fields.len() < 8 {
            return Err(invalid("invalid NFQUEUE counter row"));
        }
        let parsed = fields[..8]
            .iter()
            .map(|s| s.parse::<u32>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("invalid NFQUEUE counter value"))?;
        found = Some((parsed[1], parsed[7]));
    }
    Ok(found)
}

fn check_ports(text: &str, ports: (u16, u16)) -> io::Result<()> {
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        // Closed sockets from our previous probes can remain in TIME_WAIT.
        // They carry no application traffic and curl skips unavailable ports.
        if fields
            .get(3)
            .is_some_and(|state| matches!(*state, "06" | "07"))
        {
            continue;
        }
        let local = fields
            .get(1)
            .ok_or_else(|| invalid("invalid TCP socket row"))?;
        let (_, port) = local
            .split_once(':')
            .ok_or_else(|| invalid("invalid TCP socket address"))?;
        let port = u16::from_str_radix(port, 16).map_err(|_| invalid("invalid TCP socket port"))?;
        if (ports.0..=ports.1).contains(&port) {
            return Err(invalid("sandbox source ports are already in use"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn local_ipv4() -> io::Result<Vec<String>> {
    use std::{collections::BTreeSet, net::Ipv4Addr};
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let _addresses = Addresses(list);
    let mut ips = BTreeSet::new();
    let mut current = list;
    while !current.is_null() {
        let row = unsafe { &*current };
        if !row.ifa_addr.is_null() && unsafe { (*row.ifa_addr).sa_family as i32 } == libc::AF_INET {
            let source = unsafe { &*(row.ifa_addr.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(source.sin_addr.s_addr.to_ne_bytes());
            if !ip.is_unspecified() {
                ips.insert(ip.to_string());
            }
        }
        current = row.ifa_next;
    }
    if ips.is_empty() {
        Err(invalid("no local IPv4 addresses for sandbox isolation"))
    } else {
        Ok(ips.into_iter().collect())
    }
}

#[cfg(not(target_os = "linux"))]
fn local_ipv4() -> io::Result<Vec<String>> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Default)]
    struct Firewall {
        chains: BTreeMap<String, Vec<Vec<String>>>,
        log: Vec<Vec<String>>,
        fail: String,
    }

    #[derive(Default)]
    struct Fake(Mutex<Firewall>);

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            assert_eq!(program, "iptables");
            assert_eq!(&args[..4], ["-w", "2", "-t", "mangle"]);
            let mut f = self.0.lock().unwrap();
            f.log.push(strings(args));
            if !f.fail.is_empty() && args.join(" ").contains(&f.fail) {
                f.fail.clear();
                return Err(io::Error::other("injected firewall failure"));
            }
            let args = &args[4..];
            if args == ["-S"] {
                return Ok(f
                    .chains
                    .keys()
                    .map(|name| format!("-N {name}"))
                    .collect::<Vec<_>>()
                    .join("\n"));
            }
            let (op, name) = (args[0], args[1]);
            if op == "-N" {
                if f.chains.contains_key(name) {
                    return Err(invalid("chain exists"));
                }
                f.chains.insert(name.into(), Vec::new());
                return Ok(String::new());
            }
            if op == "-X" {
                if f.chains.get(name).is_none_or(|rules| !rules.is_empty())
                    || f.chains
                        .values()
                        .flatten()
                        .any(|rule| rule.windows(2).any(|w| w == ["-j", name]))
                {
                    return Err(invalid("chain is in use"));
                }
                f.chains.remove(name);
                return Ok(String::new());
            }
            let rules = f
                .chains
                .get_mut(name)
                .ok_or_else(|| invalid("chain missing"))?;
            let rule = strings(&args[if op == "-I" { 3 } else { 2 }..]);
            match op {
                "-A" => rules.push(rule),
                "-I" => rules.insert(0, rule),
                "-D" | "-C" => {
                    let at = rules
                        .iter()
                        .position(|r| *r == rule)
                        .ok_or_else(|| invalid("rule missing"))?;
                    if op == "-D" {
                        rules.remove(at);
                    }
                }
                _ => panic!("unexpected firewall mutation"),
            }
            Ok(String::new())
        }
    }

    fn fixture(fake: Arc<Fake>, queued: bool) -> Sandbox {
        {
            let mut f = fake.0.lock().unwrap();
            for name in [
                "OUTPUT",
                "POSTROUTING",
                "PREROUTING",
                "nfqws_post",
                "nfqws_pre",
            ] {
                f.chains.entry(name.into()).or_default();
            }
            f.chains.get_mut("nfqws_post").unwrap().push(strings(&[
                "-j",
                "NFQUEUE",
                "--queue-num",
                "300",
            ]));
        }
        Sandbox {
            config: config(),
            queue: 200,
            ports: (50000, 50199),
            next_probe_port: Cell::new(50000),
            chains: ["owned_post".into(), "owned_pre".into(), "owned_out".into()],
            tag: "owned".into(),
            created: Vec::new(),
            rules: Vec::new(),
            main_chains: Vec::new(),
            local_ips: vec!["192.0.2.2".into()],
            work: Some(tempfile::tempdir().unwrap()),
            child: None,
            queued,
            runner: fake,
            cleanup_deadline: None,
        }
    }

    fn config() -> Config {
        Config {
            nfqws_bin: "nfqws2".into(),
            wan_ifaces: vec!["eth0".into()],
            base_args: None,
            first_queue: 200,
            main_queue: 300,
            port_base: 50000,
            ports_per_worker: 200,
        }
    }

    #[test]
    fn slot_parameters_reject_queue_and_port_collisions() {
        let mut cfg = config();
        assert_eq!(parameters(&cfg, 2).unwrap(), (202, (50400, 50599)));
        assert!(parameters(&cfg, 100).is_err());
        cfg.port_base = 65500;
        assert!(parameters(&cfg, 0).is_err());
        cfg.port_base = 50000;
        cfg.wan_ifaces = vec!["eth0;bad".into()];
        assert!(parameters(&cfg, 0).is_err());
    }

    #[test]
    fn queue_sequence_uses_packet_ids_and_validates_ownership_columns() {
        assert_eq!(
            queue_row("200 1234 0 2 65535 0 0 4294967295 1", 200).unwrap(),
            Some((1234, u32::MAX))
        );
        assert_eq!(
            queue_row("200 1234 0 2 65535 0 0 0 1", 200).unwrap(),
            Some((1234, 0))
        );
        assert!(queue_row("200 1234 0 2 65535 0 0 bad", 200).is_err());
        assert!(queue_row("200 1 0 2 1 0 0 8\n200 2 0 2 1 0 0 9", 200).is_err());
        assert_eq!(queue_row("300 1234 0 2 65535 0 0 12", 200).unwrap(), None);
    }

    #[test]
    fn candidate_cannot_override_queue_or_spawn_a_daemon() {
        let mut cfg = config();
        cfg.base_args = Some(strings(&["--daemon", "--lua-init=@/safe/a.lua"]));
        let args = engine_args(
            &cfg,
            200,
            std::path::Path::new("/tmp/owned"),
            "--filter-tcp=443 --lua-desync=fake",
        )
        .unwrap();
        assert_eq!(args[0], "--qnum=200");
        assert!(!args.iter().any(|s| s == "--daemon"));
        for arg in [
            "--qnum=300",
            "-q=300",
            "--writable=/other",
            "--new",
            "--pidfile=/other",
            "--q=300",
            "-q300",
            "--writ=/other",
            "--da=1",
            "--pidf=/other",
        ] {
            assert!(engine_args(&cfg, 200, std::path::Path::new("/tmp/owned"), arg).is_err());
        }
    }

    #[test]
    fn rules_scope_original_source_and_preserve_the_vendor_chain_return() {
        let rule = queue_rule("eth0", "192.0.2.2", "50000:50199", 200, false);
        assert!(rule.windows(2).any(|w| w == ["--ctorigsrc", "192.0.2.2"]));
        assert!(rule.windows(2).any(|w| w == ["--queue-num", "200"]));
        assert!(rule
            .windows(2)
            .any(|w| w == ["--connbytes-dir", "original"]));
        let guard = main_guard("nfqws_post", "192.0.2.2", "50000:50199", "unique");
        assert_eq!(&guard[guard.len() - 2..], ["-j", "RETURN"]);
        assert!(guard.windows(2).any(|w| w == ["--comment", "unique"]));
        assert!(guard.windows(2).any(|w| w == ["--ctorigsrc", "192.0.2.2"]));
    }

    #[test]
    fn existing_router_sockets_are_never_captured() {
        let text = "header\n0: 0100007F:C350 00000000:0000 0A";
        assert!(check_ports(text, (50000, 50199)).is_err());
        assert!(check_ports(text, (50200, 50399)).is_ok());
        assert!(check_ports("header\n0: 0100007F:C350 00000000:0000 06", (50000, 50199)).is_ok());
    }

    #[test]
    fn teardown_restores_original_rules_and_never_flushes_any_chain() {
        let fake = Arc::new(Fake::default());
        let mut slot = fixture(fake.clone(), true);
        let before = fake.0.lock().unwrap().chains.clone();
        slot.install().unwrap();
        {
            let f = fake.0.lock().unwrap();
            let last = f.log.last().unwrap();
            assert_eq!(&last[4..], ["-I", "OUTPUT", "1", "-j", "owned_out"]);
        }
        slot.cleanup().unwrap();
        let f = fake.0.lock().unwrap();
        assert_eq!(before, f.chains);
        assert!(!f.log.iter().any(|args| args.iter().any(|a| a == "-F")));
    }

    #[test]
    fn partial_install_and_failed_cleanup_preserve_only_owned_state_for_retry() {
        let fake = Arc::new(Fake::default());
        let mut slot = fixture(fake.clone(), true);
        let before = fake.0.lock().unwrap().chains.clone();
        fake.0.lock().unwrap().fail = "--queue-num 200".into();
        assert!(slot.install().is_err());
        fake.0.lock().unwrap().fail = "-D owned_out".into();
        assert!(slot.cleanup().is_err());
        assert!(!slot.rules.is_empty());
        slot.cleanup().unwrap();
        assert_eq!(before, fake.0.lock().unwrap().chains);
    }

    #[test]
    fn baseline_never_queues_traffic_and_still_excludes_vendor_processing() {
        let fake = Arc::new(Fake::default());
        let mut slot = fixture(fake.clone(), false);
        slot.install().unwrap();
        {
            let f = fake.0.lock().unwrap();
            assert!(!f.chains["owned_post"]
                .iter()
                .any(|args| args.iter().any(|a| a == "NFQUEUE")));
            assert!(f.chains["nfqws_post"]
                .iter()
                .any(|args| args.last().is_some_and(|a| a == "RETURN")));
            assert!(f.chains["owned_out"]
                .iter()
                .any(|args| args.iter().any(|a| a == "CONNMARK")));
        }
        slot.cleanup().unwrap();
    }

    #[test]
    fn recovery_removes_only_the_recorded_state_after_a_killed_helper() {
        let root = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::default());
        let mut slot = fixture(fake.clone(), true);
        slot.tag = "N2SM_0123456789ab".into();
        slot.chains = [
            format!("{}_P", slot.tag),
            format!("{}_R", slot.tag),
            format!("{}_O", slot.tag),
        ];
        slot.work = Some(slot_directory(root.path()).unwrap());
        let before = fake.0.lock().unwrap().chains.clone();
        slot.install().unwrap();
        let kept = slot.work.take().unwrap().keep();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&kept).unwrap().permissions().mode() & 0o077, 0);
        }
        // Simulate abrupt death: the durable manifest is the remaining owner.
        slot.rules.clear();
        slot.created.clear();
        recover_at(root.path(), fake.as_ref()).unwrap();
        assert!(!kept.exists());
        assert_eq!(before, fake.0.lock().unwrap().chains);
    }

    #[test]
    fn recovery_rejects_unowned_rules_and_global_iptables_options() {
        let tag = "N2SM_0123456789ab";
        let mut journal = Journal {
            tag: tag.into(),
            created: vec![format!("{tag}_P")],
            rules: vec![
                Rule {
                    chain: "OUTPUT".into(),
                    args: strings(&["-j", &format!("{tag}_O")]),
                },
                Rule {
                    chain: "nfqws_post".into(),
                    args: main_guard("nfqws_post", "192.0.2.2", "50000:50199", tag),
                },
            ],
        };
        validate_journal(&journal).unwrap();
        journal.rules.push(Rule {
            chain: format!("{tag}_P"),
            args: strings(&["-t", "filter", "-F", "FORWARD"]),
        });
        assert!(validate_journal(&journal).is_err());
        journal.rules.pop();
        journal.rules[1].args.push("--some-other-option".into());
        assert!(validate_journal(&journal).is_err());
        journal.rules.pop();
        journal.created[0] = "nfqws_post".into();
        assert!(validate_journal(&journal).is_err());
    }
}
