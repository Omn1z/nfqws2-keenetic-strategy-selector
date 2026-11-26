use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io,
    net::Ipv4Addr,
    process::Command,
};

const OUT: &str = "N2S_BC_OUT";
const SKIP: &str = "N2S_BC_RETURN";
const VENDOR: [&str; 2] = ["nfqws_post", "nfqws_pre"];
const EXCLUDE: &str = "0x20000000/0x20000000";
const GENERATED: &str = "0x40000000/0x40000000";

/// Both kinds of native test helper share this process lock. Leave the empty
/// inode in place so two processes can never acquire different lock files.
pub fn exclusive() -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(unix)]
    let dir = std::path::PathBuf::from("/tmp");
    #[cfg(not(unix))]
    let dir = std::env::temp_dir();
    let file = opts.open(dir.join("nfqws2-strategy-native-test.lock"))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("invalid test lock"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // An unprivileged creator could otherwise unlink and replace the inode.
        if file.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other("foreign test lock owner"));
        }
    }
    file.try_lock().map_err(|e| {
        io::Error::other(format!("another router test owns the firewall lock: {e}"))
    })?;
    Ok(file)
}

pub trait Firewall {
    fn iptables(&self, args: &[String]) -> io::Result<String>;
    fn addresses(&self) -> io::Result<BTreeSet<Ipv4Addr>>;
}
pub struct System;
fn command(mut cmd: Command) -> io::Result<String> {
    crate::tied_to_parent(&mut cmd);
    let tool = cmd.get_program().to_string_lossy().into_owned();
    let out = cmd
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("{tool}: {e}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    Err(io::Error::other(format!(
        "{tool} {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}
impl Firewall for System {
    fn iptables(&self, args: &[String]) -> io::Result<String> {
        let mut cmd = Command::new("iptables");
        cmd.args(["-w", "5", "-t", "mangle"]).args(args);
        command(cmd)
    }
    fn addresses(&self) -> io::Result<BTreeSet<Ipv4Addr>> {
        let mut cmd = Command::new("ip");
        cmd.args(["-4", "addr", "show"]);
        let addrs: BTreeSet<_> = command(cmd)?
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                (words.next()? == "inet").then_some(())?;
                let addr: Ipv4Addr = words.next()?.split('/').next()?.parse().ok()?;
                (!addr.is_unspecified()).then_some(addr)
            })
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::other("no local IPv4 addresses"));
        }
        Ok(addrs)
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
fn table(sys: &impl Firewall) -> io::Result<String> {
    sys.iptables(&args(&["-S"]))
}
fn declared(table: &str, name: &str) -> bool {
    table
        .lines()
        .any(|line| line.split_whitespace().eq(["-N", name]))
}
fn vendor(table: &str) -> Vec<&'static str> {
    VENDOR
        .into_iter()
        .filter(|name| declared(table, name))
        .collect()
}

// Kernel listings include implicit match modules such as "-m tcp". Only
// inspect simple argument lists referencing the two reserved private chains.
// Neither foreign chains nor an entire built-in table are ever flushed.
fn owned_reference(words: &[&str]) -> bool {
    words.len() >= 4
        && words[0] == "-A"
        && match words[1] {
            "OUTPUT" => words[2..] == ["-j", OUT],
            "nfqws_pre" | "nfqws_post" => words.ends_with(&["-g", SKIP]),
            _ => false,
        }
}
fn recover(sys: &impl Firewall, listing: &str) -> io::Result<()> {
    let mut rules: Vec<Vec<_>> = listing
        .lines()
        .map(|s| s.split_whitespace().collect())
        .filter(|w: &Vec<_>| owned_reference(w))
        .collect();
    rules.sort_by_key(|w| w[1] != "OUTPUT");
    for mut rule in rules {
        rule[0] = "-D";
        sys.iptables(&args(&rule))?;
    }
    for name in [OUT, SKIP]
        .into_iter()
        .filter(|name| declared(listing, name))
    {
        sys.iptables(&args(&["-F", name]))?;
        sys.iptables(&args(&["-X", name]))?;
    }
    Ok(())
}
pub fn recover_owned() -> io::Result<()> {
    let _lock = exclusive()?;
    recover(&System, &table(&System)?)?;
    let listing = table(&System)?;
    if [OUT, SKIP].iter().any(|name| declared(&listing, name)) {
        return Err(io::Error::other(
            "private BlockCheck chains remain after rollback",
        ));
    }
    Ok(())
}

pub struct Sandbox<S: Firewall = System> {
    sys: S,
    addrs: BTreeSet<Ipv4Addr>,
    vendor: Vec<&'static str>,
    checks: Vec<Vec<String>>,
    undo: Vec<Vec<String>>,
}
impl Sandbox {
    pub fn install(ports: &[(u16, u16)]) -> io::Result<Self> {
        Self::open(System, ports)
    }
}
impl<S: Firewall> Sandbox<S> {
    /// The caller holds the cross-process lock through close(). Recover
    /// private rules left by a power interruption or SIGKILL before starting.
    pub fn open(sys: S, ports: &[(u16, u16)]) -> io::Result<Self> {
        Self::open_with(sys, ports, || Ok(()))
    }
    pub fn open_with(
        sys: S,
        ports: &[(u16, u16)],
        check_cancel: impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let mut previous = 0;
        for &(lo, hi) in ports {
            if lo <= previous || hi < lo {
                return Err(io::Error::other("invalid or overlapping worker ports"));
            }
            previous = hi;
        }
        if ports.is_empty() {
            return Err(io::Error::other("missing worker ports"));
        }
        let listing = table(&sys)?;
        recover(&sys, &listing)?;
        let addrs = sys.addresses()?;
        let vendor = vendor(&listing);
        let mut sandbox = Self {
            sys,
            addrs,
            vendor,
            checks: Vec::new(),
            undo: Vec::new(),
        };
        if let Err(e) = sandbox
            .install_rules(ports, check_cancel)
            .and_then(|_| sandbox.verify())
        {
            return match sandbox.close() {
                Ok(()) => Err(e),
                Err(clean) => Err(io::Error::other(format!("{e}; firewall rollback: {clean}"))),
            };
        }
        Ok(sandbox)
    }
    fn create(&mut self, name: &str) -> io::Result<()> {
        self.sys.iptables(&args(&["-N", name]))?;
        self.undo.push(args(&["-X", name]));
        Ok(())
    }
    fn rule(&mut self, chain: &str, first: bool, matches: &[&str]) -> io::Result<()> {
        let mut add = if first {
            args(&["-I", chain, "1"])
        } else {
            args(&["-A", chain])
        };
        add.extend(args(matches));
        self.sys.iptables(&add)?;
        let mut check = args(&["-C", chain]);
        check.extend(args(matches));
        let mut del = check.clone();
        del[0] = "-D".into();
        self.checks.push(check);
        self.undo.push(del);
        Ok(())
    }
    fn install_rules(
        &mut self,
        ports: &[(u16, u16)],
        check_cancel: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check_cancel()?;
        self.create(OUT)?;
        self.create(SKIP)?;
        // A goto to an empty user chain returns to the vendor chain's caller,
        // preserving subsequent unrelated PREROUTING/POSTROUTING rules.
        self.rule(
            OUT,
            false,
            &["-m", "mark", "--mark", GENERATED, "-j", "RETURN"],
        )?;
        for &(lo, hi) in ports {
            check_cancel()?;
            let range = format!("{lo}:{hi}");
            self.rule(
                OUT,
                false,
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "443",
                    "--sport",
                    &range,
                    "-j",
                    "CONNMARK",
                    "--set-xmark",
                    EXCLUDE,
                ],
            )?;
            for chain in self.vendor.clone() {
                let (source, dest) = if chain == "nfqws_post" {
                    (range.as_str(), "443")
                } else {
                    ("443", range.as_str())
                };
                for addr in self.addrs.clone() {
                    check_cancel()?;
                    self.rule(
                        chain,
                        true,
                        &[
                            "-p",
                            "tcp",
                            "--sport",
                            source,
                            "--dport",
                            dest,
                            "-m",
                            "connmark",
                            "--mark",
                            EXCLUDE,
                            "-m",
                            "conntrack",
                            "--ctorigsrc",
                            &addr.to_string(),
                            "-g",
                            SKIP,
                        ],
                    )?;
                }
            }
        }
        // Never start marking until every vendor guard is installed.
        check_cancel()?;
        self.rule("OUTPUT", true, &["-j", OUT])
    }
    pub fn verify(&self) -> io::Result<()> {
        let listing = table(&self.sys)?;
        if self.addrs != self.sys.addresses()? || self.vendor != vendor(&listing) {
            return Err(io::Error::other(
                "router IPv4 addresses or NFQWS2 chains changed during test",
            ));
        }
        if !declared(&listing, SKIP)
            || listing
                .lines()
                .any(|l| l.split_whitespace().take(2).eq(["-A", SKIP]))
        {
            return Err(io::Error::other("vendor return chain was modified"));
        }
        for check in &self.checks {
            self.sys.iptables(check)?;
        }
        for chain in std::iter::once("OUTPUT").chain(self.vendor.iter().copied()) {
            let required = self.checks.iter().filter(|c| c[1] == chain).count();
            let top = listing
                .lines()
                .map(|l| l.split_whitespace().collect::<Vec<_>>())
                .filter(|w| w.len() > 1 && w[0] == "-A" && w[1] == chain)
                .take_while(|w| owned_reference(w))
                .count();
            if top != required {
                return Err(io::Error::other(format!(
                    "isolation rules no longer first in {chain}"
                )));
            }
        }
        let mut out = listing
            .lines()
            .filter(|l| l.split_whitespace().take(2).eq(["-A", OUT]));
        let skip_generated_first = out
            .next()
            .is_some_and(|line| line.split_whitespace().next_back() == Some("RETURN"));
        if !skip_generated_first
            || out.count() + 1 != self.checks.iter().filter(|c| c[1] == OUT).count()
        {
            return Err(io::Error::other("router OUTPUT marker chain was modified"));
        }
        Ok(())
    }
    pub fn close(&mut self) -> io::Result<()> {
        let mut failed = Vec::new();
        let mut errors = Vec::new();
        while let Some(cmd) = self.undo.pop() {
            if let Err(e) = self.sys.iptables(&cmd) {
                errors.push(e.to_string());
                failed.push(cmd);
            }
        }
        failed.reverse();
        self.undo = failed;
        if !errors.is_empty() {
            return Err(io::Error::other(errors.join("; ")));
        }
        Ok(())
    }
}
impl<S: Firewall> Drop for Sandbox<S> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
