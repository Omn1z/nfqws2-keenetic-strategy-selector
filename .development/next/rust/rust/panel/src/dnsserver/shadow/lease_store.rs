use super::{discovery, leases};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime, UtcOffset};

const FILE: &str = "shadow-dns-leases.json";
const LIMIT: u64 = 16 * 1024;
pub(super) const MAX_RECORDS: usize = 8;
const MAX_LEASE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub(super) struct Clock {
    boot: String,
    uptime: Duration,
    wall: OffsetDateTime,
    monotonic: Instant,
}

impl Clock {
    pub(super) fn read(root: &Path) -> io::Result<Self> {
        let boot = fs::read_to_string(root.join("proc/sys/kernel/random/boot_id"))?;
        let boot = boot.trim();
        let uptime = fs::read_to_string(root.join("proc/uptime"))?;
        let seconds = uptime
            .split_ascii_whitespace()
            .next()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|seconds| (0.0..=1e9).contains(seconds))
            .ok_or_else(invalid)?;
        if !valid_boot(boot) {
            return Err(invalid());
        }
        Ok(Self {
            boot: boot.to_owned(),
            uptime: Duration::from_nanos((seconds * 1e9) as u64),
            wall: OffsetDateTime::now_utc(),
            monotonic: Instant::now(),
        })
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Shadow DNS lease receipt",
    )
}

fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 2048 && !key.contains(['\r', '\n', '\0'])
}

fn valid_stamp(stamp: &str) -> bool {
    // The firmware timestamp omits the year. This leap year validates all
    // dates Go accepts, including February 29, without interpreting its age.
    let reference = Date::from_calendar_date(2000, Month::December, 31)
        .unwrap()
        .with_hms(23, 59, 59)
        .unwrap()
        .assume_utc();
    leases::observed_at(stamp, reference).is_some()
}

fn wall_time(text: &str) -> io::Result<OffsetDateTime> {
    let value = OffsetDateTime::parse(text, &Rfc3339).map_err(|_| invalid())?;
    if value.unix_timestamp_nanos() == -62_135_596_800_000_000_000 {
        return Err(invalid());
    }
    Ok(value)
}

fn wall_text(value: OffsetDateTime) -> io::Result<String> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(io::Error::other)
}

fn client_ip(text: &str) -> io::Result<Ipv4Addr> {
    match text.parse::<IpAddr>().ok().map(|ip| ip.to_canonical()) {
        Some(IpAddr::V4(ip)) if discovery::usable(ip.into()) => Ok(ip),
        _ => Err(invalid()),
    }
}

fn endpoint(text: &str) -> io::Result<SocketAddr> {
    let addr = text
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .or_else(|_| text.parse::<SocketAddr>())
        .map_err(|_| invalid())?;
    let ip = addr.ip().to_canonical();
    if addr.port() == 0
        || !discovery::usable(ip)
        || matches!(addr, SocketAddr::V6(addr) if addr.scope_id() != 0)
    {
        return Err(invalid());
    }
    Ok(SocketAddr::new(ip, addr.port()))
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Lease {
    pub(super) wan_key: String,
    pub(super) client: Ipv4Addr,
    pub(super) servers: Vec<SocketAddr>,
    pub(super) expires: Instant,
    pub(super) stamp: String,
    pub(super) lease_seconds: u32,
    pub(super) observed_at: Option<OffsetDateTime>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) wan_key: String,
    pub(super) client: Ipv4Addr,
    pub(super) server: Ipv4Addr,
    pub(super) stamp: String,
}

#[derive(Default, Clone, PartialEq, Eq)]
pub(super) struct State {
    pub(super) leases: BTreeMap<String, Lease>,
    pub(super) targets: BTreeMap<String, Target>,
}

/// A DNS Server may replace its listeners while the owning panel stays up.
/// Retain validated evidence across those runs even if an atomic write needs a retry.
pub(super) struct File {
    store: Store,
    router_root: PathBuf,
    memory: Mutex<Option<Memory>>,
}

struct Memory {
    current: State,
    written: State,
}

impl File {
    pub(super) fn new(store: Store, router_root: PathBuf) -> Self {
        Self {
            store,
            router_root,
            memory: Mutex::new(None),
        }
    }

    fn load(&self) -> Memory {
        let restored = Clock::read(&self.router_root)
            .and_then(|clock| State::load(&self.store, &clock))
            .unwrap_or_default();
        Memory {
            current: restored.clone(),
            written: restored,
        }
    }

    pub(super) fn snapshot(&self) -> State {
        self.memory
            .lock()
            .unwrap()
            .get_or_insert_with(|| self.load())
            .current
            .clone()
    }

    #[cfg(test)]
    pub(super) fn update_leases(&self, leases: BTreeMap<String, Lease>) -> io::Result<()> {
        self.update(leases, None)
    }

    pub(super) fn update(
        &self,
        leases: BTreeMap<String, Lease>,
        targets: Option<BTreeMap<String, Target>>,
    ) -> io::Result<()> {
        let mut state = self.memory.lock().unwrap();
        let state = state.get_or_insert_with(|| self.load());
        state.current.leases = leases;
        if let Some(targets) = targets {
            state.current.targets = targets;
        }
        if state.current != state.written {
            let clock = Clock::read(&self.router_root)?;
            state.current.save(&self.store, &clock)?;
            state.written = state.current.clone();
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    boot_id: String,
    saved_at: String,
    saved_boot_ns: u64,
    leases: Option<Vec<LeaseRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dhcp_targets: Option<Vec<TargetRow>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseRow {
    interface: String,
    wan_key: String,
    client_ip: String,
    servers: Vec<String>,
    expires: String,
    expires_boot_ns: u64,
    dhcp_stamp: String,
    lease_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetRow {
    interface: String,
    wan_key: String,
    client_ip: String,
    server_ip: String,
    dhcp_stamp: String,
}

impl Document {
    fn restore(&self, clock: &Clock) -> io::Result<State> {
        let saved = wall_time(&self.saved_at)?;
        let saved_boot = Duration::from_nanos(self.saved_boot_ns);
        let leases = self.leases.as_deref().unwrap_or_default();
        let targets = self.dhcp_targets.as_deref().unwrap_or_default();
        if self.version != 1
            || self.boot_id != clock.boot
            || saved > clock.wall
            || saved_boot > clock.uptime
            || leases.len() > MAX_RECORDS
            || targets.len() > MAX_RECORDS
        {
            return Err(invalid());
        }
        let mut state = State::default();
        let mut seen = BTreeSet::new();
        for row in leases {
            if !discovery::native(&row.interface)
                || !valid_key(&row.wan_key)
                || row.dhcp_stamp.len() > 32
                || matches!(row.lease_seconds, 0 | u32::MAX)
                || row.servers.is_empty()
                || row.servers.len() > MAX_RECORDS
                || !seen.insert(&row.interface)
            {
                return Err(invalid());
            }
            let client = client_ip(&row.client_ip)?;
            let servers = row
                .servers
                .iter()
                .map(|value| endpoint(value))
                .collect::<io::Result<Vec<_>>>()?;
            if servers.iter().copied().collect::<BTreeSet<_>>().len() != servers.len() {
                return Err(invalid());
            }
            let wall_expiry = wall_time(&row.expires)?;
            let boot_expiry = Duration::from_nanos(row.expires_boot_ns);
            let lease = Duration::from_secs(u64::from(row.lease_seconds));
            let observed_at = row.observed_at.as_deref().map(wall_time).transpose()?;
            match observed_at {
                Some(at) if at > saved || wall_expiry > at + lease => return Err(invalid()),
                None if !valid_stamp(&row.dhcp_stamp) => return Err(invalid()),
                _ => {}
            }
            let maximum = MAX_LEASE.min(lease);
            if wall_expiry <= saved
                || wall_expiry > saved + maximum
                || boot_expiry <= saved_boot
                || boot_expiry - saved_boot > maximum
            {
                return Err(invalid());
            }
            if wall_expiry <= clock.wall || boot_expiry <= clock.uptime {
                continue;
            }
            let remaining = Duration::try_from(wall_expiry - clock.wall)
                .map_err(|_| invalid())?
                .min(boot_expiry - clock.uptime);
            state.leases.insert(
                row.interface.clone(),
                Lease {
                    wan_key: row.wan_key.clone(),
                    client,
                    servers,
                    expires: clock.monotonic + remaining,
                    stamp: row.dhcp_stamp.clone(),
                    lease_seconds: row.lease_seconds,
                    observed_at,
                },
            );
        }
        for row in targets {
            let client = client_ip(&row.client_ip)?;
            let server = client_ip(&row.server_ip)?;
            if !discovery::native(&row.interface)
                || !valid_key(&row.wan_key)
                || client == server
                || (!row.dhcp_stamp.is_empty() && !valid_stamp(&row.dhcp_stamp))
            {
                return Err(invalid());
            }
            let target = Target {
                wan_key: row.wan_key.clone(),
                client,
                server,
                stamp: row.dhcp_stamp.clone(),
            };
            if state
                .targets
                .insert(row.interface.clone(), target)
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(state)
    }
}

impl State {
    pub(super) fn load(store: &Store, clock: &Clock) -> io::Result<Self> {
        let value: Document = store.read_limited(FILE, LIMIT)?;
        value.restore(clock)
    }

    pub(super) fn save(&self, store: &Store, clock: &Clock) -> io::Result<()> {
        let boot_ns = |age: Duration| u64::try_from(age.as_nanos()).map_err(|_| invalid());
        if self.leases.len() > MAX_RECORDS || self.targets.len() > MAX_RECORDS {
            return Err(invalid());
        }
        let mut leases = Vec::new();
        for (iface, lease) in &self.leases {
            let time_left = lease.expires.saturating_duration_since(clock.monotonic);
            if time_left.is_zero() {
                continue;
            }
            if time_left > MAX_LEASE {
                return Err(invalid());
            }
            leases.push(LeaseRow {
                interface: iface.clone(),
                wan_key: lease.wan_key.clone(),
                client_ip: lease.client.to_string(),
                servers: lease.servers.iter().map(SocketAddr::to_string).collect(),
                expires: wall_text(clock.wall + time_left)?,
                expires_boot_ns: boot_ns(clock.uptime + time_left)?,
                dhcp_stamp: lease.stamp.clone(),
                lease_seconds: lease.lease_seconds,
                observed_at: lease.observed_at.map(wall_text).transpose()?,
            });
        }
        let dhcp_targets = (!self.targets.is_empty()).then(|| {
            self.targets
                .iter()
                .map(|(iface, target)| TargetRow {
                    interface: iface.clone(),
                    wan_key: target.wan_key.clone(),
                    client_ip: target.client.to_string(),
                    server_ip: target.server.to_string(),
                    dhcp_stamp: target.stamp.clone(),
                })
                .collect()
        });
        let doc = Document {
            version: 1,
            boot_id: clock.boot.clone(),
            saved_at: wall_text(clock.wall)?,
            saved_boot_ns: boot_ns(clock.uptime)?,
            leases: Some(leases),
            dhcp_targets,
        };
        doc.restore(clock)?;
        store.try_transaction(|tx| tx.save_bounded(FILE, &doc, LIMIT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GO_FIXTURE: &str = r#"{
        "version":1,"boot_id":"01234567-89ab-cdef-0123-456789abcdef",
        "saved_at":"2026-10-03T12:00:00Z","saved_boot_ns":43200000000000,
        "leases":[{"interface":"ISP","wan_key":"ip=192.168.0.10|route=eth3/192.168.0.1",
            "client_ip":"192.168.0.10","servers":["192.0.2.53:53","[2001:db8::53]:53"],
            "expires":"2026-10-03T13:00:00Z","expires_boot_ns":46800000000000,
            "dhcp_stamp":"Oct  3 11:00:00","lease_seconds":7200}],
        "dhcp_targets":[{"interface":"ISP","wan_key":"ip=192.168.0.10|route=eth3/192.168.0.1",
            "client_ip":"192.168.0.10","server_ip":"192.168.0.1","dhcp_stamp":""}]
    }"#;

    fn fixture() -> (tempfile::TempDir, Store, Clock) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        fs::write(dir.path().join(FILE), GO_FIXTURE).unwrap();
        let clock = Clock {
            boot: "01234567-89ab-cdef-0123-456789abcdef".into(),
            uptime: Duration::from_secs(43_200),
            wall: wall_time("2026-10-03T12:00:00Z").unwrap(),
            monotonic: Instant::now(),
        };
        (dir, store, clock)
    }

    #[test]
    fn restores_go_leases_with_earliest_clock_and_keeps_independent_target() {
        let (_dir, store, mut clock) = fixture();
        let elapsed = Duration::from_secs(20 * 60);
        clock.monotonic += elapsed;
        clock.uptime += elapsed;
        clock.wall += Duration::from_secs(10 * 60);
        let state = State::load(&store, &clock).unwrap();
        let lease = &state.leases["ISP"];
        assert_eq!(
            lease.expires - clock.monotonic,
            Duration::from_secs(40 * 60)
        );
        assert_eq!(lease.servers[1], "[2001:db8::53]:53".parse().unwrap());
        assert_eq!(state.targets["ISP"].server, Ipv4Addr::new(192, 168, 0, 1));
        clock.uptime += Duration::from_secs(40 * 60);
        let expired = State::load(&store, &clock).unwrap();
        assert!(expired.leases.is_empty());
        assert_eq!(expired.targets["ISP"].client, lease.client);
    }

    #[test]
    fn rejects_wrong_boot_rollback_invalid_rows_and_extra_wire() {
        let (dir, store, mut clock) = fixture();
        clock.boot.replace_range(0..1, "f");
        assert!(State::load(&store, &clock).is_err());
        clock.boot.replace_range(0..1, "0");
        clock.uptime -= Duration::from_secs(1);
        assert!(State::load(&store, &clock).is_err());
        clock.uptime += Duration::from_secs(1);
        clock.wall -= Duration::from_secs(1);
        assert!(State::load(&store, &clock).is_err());
        clock.wall += Duration::from_secs(1);
        for wire in [
            GO_FIXTURE.replace("192.0.2.53:53", "127.0.0.1:53"),
            GO_FIXTURE.replace("192.0.2.53:53", "[2001:db8::53]:53"),
            GO_FIXTURE.replace("ISP", "Wireguard0"),
            GO_FIXTURE.replace("46800000000000", "99000000000000"),
            GO_FIXTURE.replace("192.168.0.1\",\"dhcp_stamp", "192.168.0.10\",\"dhcp_stamp"),
            GO_FIXTURE.replace("\"version\":1", "\"version\":1,\"unexpected\":true"),
            GO_FIXTURE.to_owned() + "{}",
            " ".repeat(LIMIT as usize + 1),
        ] {
            fs::write(dir.path().join(FILE), &wire).unwrap();
            assert!(State::load(&store, &clock).is_err());
        }
    }

    #[test]
    fn writes_legacy_schema_atomically_and_rejects_oversized_replacement() {
        let (dir, store, clock) = fixture();
        let mut state = State::load(&store, &clock).unwrap();
        state.save(&store, &clock).unwrap();
        let written = fs::read(dir.path().join(FILE)).unwrap();
        let loaded = State::load(&store, &clock).unwrap();
        assert!(loaded == state);
        let mut target = state.targets["ISP"].clone();
        target.wan_key = "x".repeat(2048);
        for id in 1..8 {
            state.targets.insert(format!("ISP{id}"), target.clone());
        }
        let mut lease = state.leases["ISP"].clone();
        lease.wan_key = target.wan_key.clone();
        state.leases.insert("ISP1".into(), lease);
        assert!(state.save(&store, &clock).is_err());
        assert_eq!(fs::read(dir.path().join(FILE)).unwrap(), written);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.path().join(FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn shared_lease_file_skips_unchanged_state_and_retries_a_busy_writer() {
        let (dir, store, fixture_clock) = fixture();
        let router = dir.path().join("router");
        let boot = router.join("proc/sys/kernel/random/boot_id");
        fs::create_dir_all(boot.parent().unwrap()).unwrap();
        fs::write(boot, &fixture_clock.boot).unwrap();
        fs::write(router.join("proc/uptime"), "43200.00 72000.00\n").unwrap();
        let clock = Clock::read(&router).unwrap();
        let mut state = State::load(&store, &fixture_clock).unwrap();
        state.leases.get_mut("ISP").unwrap().expires = clock.monotonic + Duration::from_secs(300);
        state.save(&store, &clock).unwrap();
        let file = File::new(store.clone(), router);
        let saved = file.snapshot();
        assert_eq!(saved.leases.len(), 1);
        let original = fs::read(dir.path().join(FILE)).unwrap();
        file.update_leases(saved.leases).unwrap();
        assert_eq!(fs::read(dir.path().join(FILE)).unwrap(), original);
        store
            .transaction(|_| {
                let removed = file.update_leases(BTreeMap::new());
                assert!(removed.is_err());
                assert!(file.snapshot().leases.is_empty());
                assert_eq!(fs::read(dir.path().join(FILE)).unwrap(), original);
                Ok(())
            })
            .unwrap();
        file.update_leases(BTreeMap::new()).unwrap();
        let restarted = File::new(store, file.router_root.clone()).snapshot();
        assert!(restarted.leases.is_empty());
        assert_eq!(restarted.targets.len(), 1);
    }
}
