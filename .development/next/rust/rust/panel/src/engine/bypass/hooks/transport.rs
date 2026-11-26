//! Replace UDP transport pairs in the applied bypass, without reading the
//! domain, address-list, or ipset inputs used by a full helper run.
use super::{files, HELPER};
use nfqws2_router_command::Runner;
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt::Write,
    fs, io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[cfg(test)]
mod tests;

const CHAIN: &str = "nfqws2_bypass";
const PARENTS: [&str; 2] = ["nfqws_post", "nfqws_pre"];
const INPUT_LIMIT: usize = 1 << 20;
const TABLE_LIMIT: usize = 24 << 20;
const TRANSPORT_LIMIT: usize = 4096;

const INSPECT: &str = r#"
if ! command -v "$1" >/dev/null 2>&1; then printf '%s\n' n2s-inactive; exit 0; fi
rc=0
"$1" -w 2 -t mangle -S 2>/dev/null || rc=$?
if [ "$rc" = 2 ]; then
    rc=0
    "$1" -t mangle -S 2>/dev/null || rc=$?
fi
[ "$rc" != 0 ] || exit 0
if [ "$rc" != 4 ] && [ "$1" = ip6tables ] && ! grep -qx mangle "$2" 2>/dev/null; then
    printf '%s\n' n2s-inactive
    exit 0
fi
exit "$rc"
"#;

pub(in crate::engine::bypass) struct TransportRefresh<'a> {
    pub root: &'a Path,
    pub helper: &'a Path,
    pub old: &'a str,
    pub new: &'a str,
    pub live: bool,
    pub deadline: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn tool(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    fn restore(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }

    fn set(self) -> &'static str {
        match self {
            Self::V4 => "n2s_nfqb4",
            Self::V6 => "n2s_nfqb6",
        }
    }

    fn accepts(self, ip: IpAddr) -> bool {
        ip.is_ipv4() == (self == Self::V4)
    }
}

struct Lock(PathBuf);

impl Lock {
    fn acquire(root: &Path, family: Family) -> io::Result<Self> {
        let path = root
            .join("tmp")
            .join(format!("nfqws-bypass-{}.lock", family.tool()));
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path)
        };
        #[cfg(not(unix))]
        let result = fs::create_dir(&path);
        match result {
            Ok(()) => Ok(Self(path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // The existing helper never removes another writer's directory.
        let _ = fs::remove_dir(&self.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Direction {
    Destination,
    Source,
}

impl Direction {
    fn switches(self) -> (&'static str, &'static str) {
        match self {
            Self::Destination => ("-d", "--dport"),
            Self::Source => ("-s", "--sport"),
        }
    }
}

type Tuple = (SocketAddr, Direction);

#[derive(Clone, Debug)]
struct Rule {
    text: String,
    transport: Option<Tuple>,
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        match (self.transport, other.transport) {
            (Some(x), Some(y)) => x == y,
            (None, None) => self.text == other.text,
            _ => false,
        }
    }
}

impl Rule {
    fn new_transport(tuple @ (endpoint, direction): Tuple) -> Self {
        let (address, port) = direction.switches();
        Self {
            text: format!(
                "{address} {} -p udp -m udp {port} {} -j ACCEPT",
                endpoint.ip(),
                endpoint.port()
            ),
            transport: Some(tuple),
        }
    }

    fn parse(text: &str, family: Family) -> io::Result<Self> {
        if text
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
        {
            return Err(ownership());
        }
        let mut args = [""; 10];
        let mut len = 0;
        for token in text.split_ascii_whitespace() {
            *args.get_mut(len).ok_or_else(ownership)? = token;
            len += 1;
        }
        let transport = match &args[..len] {
            ["-m", "set", "--match-set", set, "dst" | "src", "-j", "ACCEPT"]
                if *set == family.set() =>
            {
                None
            }
            ["-j", "ACCEPT"] => None, // xtables omits a linear /0 destination or source.
            ["-s" | "-d", ip, "-j", "ACCEPT"] if subnet(ip, family).is_some() => None,
            [side, ip, "-p", "udp", "-m", "udp", port_flag, port, "-j", "ACCEPT"]
            | [side, ip, "-p", "udp", port_flag, port, "-j", "ACCEPT"] => {
                let direction = match (*side, *port_flag) {
                    ("-s", "--sport") => Direction::Source,
                    ("-d", "--dport") => Direction::Destination,
                    _ => return Err(ownership()),
                };
                let (ip, bits) = subnet(ip, family).ok_or_else(ownership)?;
                let full = if ip.is_ipv4() { 32 } else { 128 };
                let port = port
                    .parse()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(ownership)?;
                if bits != full {
                    return Err(ownership());
                }
                Some((SocketAddr::new(ip, port), direction))
            }
            _ => return Err(ownership()),
        };
        Ok(Self {
            text: text.into(),
            transport,
        })
    }
}

fn ownership() -> io::Error {
    io::Error::other("Не подтверждены действующие правила NFQUEUE bypass")
}

fn subnet(raw: &str, family: Family) -> Option<(IpAddr, u8)> {
    let (raw, bits) = raw
        .split_once('/')
        .map_or((raw, None), |(ip, bits)| (ip, Some(bits)));
    let ip: IpAddr = raw.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let bits = bits.map_or(Some(max), |bits| bits.parse().ok())?;
    (family.accepts(ip) && bits <= max).then_some((ip, bits))
}

fn endpoints(input: &str) -> io::Result<BTreeSet<SocketAddr>> {
    if input.len() > INPUT_LIMIT {
        return Err(io::Error::other(
            "Список AWG endpoint превышает предел NFQUEUE",
        ));
    }
    let mut out = BTreeSet::new();
    for line in input.lines() {
        let mut fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace();
        let (Some(raw), Some(port), None) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if !port.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let (Ok(ip), Ok(port)) = (raw.parse::<IpAddr>(), port.parse()) else {
            continue;
        };
        if port == 0 || (ip.is_ipv6() && raw.contains('.')) {
            continue;
        }
        out.insert(SocketAddr::new(ip, port));
        if out.len() > TRANSPORT_LIMIT {
            return Err(io::Error::other("Слишком много AWG endpoint для NFQUEUE"));
        }
    }
    Ok(out)
}

#[derive(Debug, PartialEq)]
struct Snapshot(Vec<Rule>);

impl Snapshot {
    fn parse(raw: &str, family: Family) -> io::Result<Option<Self>> {
        if raw == "n2s-inactive" {
            return Ok(None);
        }
        if raw.is_empty() {
            return Err(ownership());
        }
        let chains: BTreeSet<_> = raw
            .lines()
            .filter_map(|line| line.strip_prefix("-N "))
            .collect();
        match PARENTS.map(|chain| chains.contains(chain)) {
            [false, false] => return Ok(None),
            [true, true] if chains.contains(CHAIN) => (),
            _ => return Err(ownership()),
        }
        let (mut attached, mut first) = ([false; 2], [true; 2]);
        let mut rules = Vec::new();
        let mut pairs = BTreeSet::new();
        // The global snapshot lets us reject references to our bypass from a
        // third chain without copying any of that chain's text into restore.
        for line in raw.lines() {
            if let Some((name, text)) = line
                .strip_prefix("-A ")
                .and_then(|rule| rule.split_once(' '))
            {
                let parent = PARENTS.iter().position(|parent| *parent == name);
                let fields = text.split_ascii_whitespace();
                let jumps_here = fields.clone().zip(fields.skip(1)).any(|(flag, target)| {
                    matches!(flag, "-j" | "-g" | "--jump" | "--goto") && target == CHAIN
                });
                if jumps_here {
                    let index = parent.ok_or_else(ownership)?;
                    if text != "-j nfqws2_bypass" || !first[index] || attached[index] {
                        return Err(ownership());
                    }
                    attached[index] = true;
                }
                if let Some(index) = parent {
                    first[index] = false;
                }
                if name == CHAIN {
                    let rule = Rule::parse(text, family)?;
                    if rule.transport.is_some_and(|key| !pairs.insert(key)) {
                        return Err(ownership());
                    }
                    rules.push(rule);
                }
            }
        }
        (attached == [true, true])
            .then_some(Self(rules))
            .ok_or_else(ownership)
            .map(Some)
    }

    fn inspect(
        runner: &impl Runner,
        family: Family,
        root: &Path,
        deadline: Instant,
    ) -> io::Result<Option<Self>> {
        let proc = root.join("proc/net/ip6_tables_names");
        let proc = proc.to_str().ok_or(io::ErrorKind::InvalidInput)?;
        let raw = runner.run_bounded(
            "sh",
            &["-c", INSPECT, "n2s-transport-inspect", family.tool(), proc],
            deadline,
            TABLE_LIMIT,
        )?;
        Self::parse(&raw, family)
    }

    fn pairs(&self) -> BTreeSet<Tuple> {
        self.0.iter().filter_map(|rule| rule.transport).collect()
    }

    fn project(
        &self,
        family: Family,
        old: &BTreeSet<SocketAddr>,
        next: &BTreeSet<SocketAddr>,
    ) -> io::Result<Self> {
        let pairs = self.pairs();
        let directions = [Direction::Destination, Direction::Source];
        for &ep in old.union(next).filter(|ep| family.accepts(ep.ip())) {
            if pairs.contains(&(ep, Direction::Destination))
                != pairs.contains(&(ep, Direction::Source))
            {
                return Err(ownership());
            }
        }
        let mut rules: Vec<_> = self
            .0
            .iter()
            .filter(|rule| {
                rule.transport
                    .is_none_or(|(ep, _)| !old.contains(&ep) || next.contains(&ep))
            })
            .cloned()
            .collect();
        let first_static = rules
            .iter()
            .position(|rule| rule.transport.is_none())
            .unwrap_or(rules.len());
        let additions = next
            .iter()
            .filter(|ep| {
                family.accepts(ep.ip()) && !pairs.contains(&(**ep, Direction::Destination))
            })
            .flat_map(|&ep| directions.map(|dir| Rule::new_transport((ep, dir))));
        rules.splice(first_static..first_static, additions);
        Ok(Self(rules))
    }

    fn apply(
        &self,
        next: &Self,
        runner: &impl Runner,
        family: Family,
        deadline: Instant,
    ) -> io::Result<()> {
        let current_pairs = self.pairs();
        let next_pairs = next.pairs();
        let mut rules = String::from("*mangle\n");
        for rule in self
            .0
            .iter()
            .filter(|rule| rule.transport.is_some_and(|x| !next_pairs.contains(&x)))
        {
            writeln!(rules, "-D {CHAIN} {}", rule.text).unwrap();
        }
        for (index, rule) in next
            .0
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.transport.is_some_and(|x| !current_pairs.contains(&x)))
        {
            writeln!(rules, "-I {CHAIN} {} {}", index + 1, rule.text).unwrap();
        }
        rules.push_str("COMMIT\n");
        runner.run_input(family.restore(), &["--noflush"], rules.as_bytes(), deadline)?;
        Ok(())
    }
}

struct Change {
    family: Family,
    prior: Snapshot,
    next: Snapshot,
}

impl Change {
    fn commit(&self, runner: &impl Runner, root: &Path, deadline: Instant) -> io::Result<()> {
        if Snapshot::inspect(runner, self.family, root, deadline)?.as_ref() != Some(&self.prior) {
            return Err(ownership());
        }
        self.prior
            .apply(&self.next, runner, self.family, deadline)?;
        if Snapshot::inspect(runner, self.family, root, deadline)?.as_ref() != Some(&self.next) {
            return Err(ownership());
        }
        Ok(())
    }

    fn rollback(&self, runner: &impl Runner, root: &Path, deadline: Instant) -> io::Result<()> {
        let current = Snapshot::inspect(runner, self.family, root, deadline)?;
        if current.as_ref() == Some(&self.prior) {
            return Ok(());
        }
        let current = current
            .filter(|actual| actual == &self.next)
            .ok_or_else(ownership)?;
        current.apply(&self.prior, runner, self.family, deadline)?;
        if Snapshot::inspect(runner, self.family, root, deadline)?.as_ref() != Some(&self.prior) {
            return Err(ownership());
        }
        Ok(())
    }
}

/// Publish only after validating both live families. On failure, compensate
/// only a family that still matches the exact old or proposed rule sequence.
pub(in crate::engine::bypass) fn refresh_transport(
    request: TransportRefresh<'_>,
    runner: &impl Runner,
    publish: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if request.helper.file_name() != Some(OsStr::new("nfqws-strategy-bypass.sh"))
        || files::read(request.helper, 2 << 20)?.as_deref() != Some(HELPER)
    {
        return Err(ownership());
    }
    let old = endpoints(request.old)?;
    let new = endpoints(request.new)?;
    let _ipv4 = Lock::acquire(request.root, Family::V4)?;
    let _ipv6 = Lock::acquire(request.root, Family::V6)?;
    if !request.live {
        return publish();
    }
    let mut changes = Vec::new();
    for family in [Family::V4, Family::V6] {
        if let Some(prior) = Snapshot::inspect(runner, family, request.root, request.deadline)? {
            let next = prior.project(family, &old, &new)?;
            if prior != next {
                changes.push(Change {
                    family,
                    prior,
                    next,
                });
            }
        }
    }
    let mut attempted = 0;
    let result = (|| {
        for change in &changes {
            attempted += 1;
            change.commit(runner, request.root, request.deadline)?;
        }
        publish()
    })();
    if result.is_err() {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut restored = true;
        for change in changes[..attempted].iter().rev() {
            restored &= change.rollback(runner, request.root, deadline).is_ok();
        }
        if !restored {
            return Err(io::Error::other(
                "Отмена обновления транспортных исключений NFQUEUE не подтверждена",
            ));
        }
    }
    result
}
