use super::{super::bounded::Bounded, Record, SourceQuery, LIMIT};
use nfqws2_dns::{MAX_ROUTE_ANSWER_ADDRESSES, MAX_ROUTE_ANSWER_TTL};
use nfqws2_store::{Store, Transaction};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, net::IpAddr, path::Path, time::Duration};
use tokio::time::Instant;

const FILE: &str = "awg-dns-recent.json";
// Include JSON keys, a 253-octet DNS name and a textual endpoint per row.
// An address in IPv6 notation occupies at most 48 bytes with quotes and comma.
const FILE_LIMIT: u64 = 128 + LIMIT as u64 * (640 + MAX_ROUTE_ANSWER_ADDRESSES as u64 * 48);
const MAX_TTL_NS: u64 = MAX_ROUTE_ANSWER_TTL as u64 * 1_000_000_000;

pub(super) struct Clock {
    ns: u64,
    instant: Instant,
}

impl Clock {
    pub(super) fn for_save() -> io::Result<Self> {
        let ns = monotonic_ns()?;
        Ok(Self {
            ns,
            instant: Instant::now(),
        })
    }

    pub(super) fn for_load() -> io::Result<Self> {
        let instant = Instant::now();
        let ns = monotonic_ns()?;
        // Sample in the opposite order from save so the clock read cannot
        // extend the lifetime on either side of a daemon restart.
        Ok(Self { ns, instant })
    }
}

#[cfg(target_os = "linux")]
fn monotonic_ns() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // `ts` is writable and clock_gettime initializes it on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(ts.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(u64::try_from(ts.tv_nsec).ok()?))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

#[cfg(not(target_os = "linux"))]
fn monotonic_ns() -> io::Result<u64> {
    Err(io::ErrorKind::Unsupported.into())
}

pub(super) fn boot_id(root: &Path) -> Option<String> {
    let value = std::fs::read_to_string(root.join("proc/sys/kernel/random/boot_id")).ok()?;
    let id = value.trim();
    (id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        }))
    .then(|| id.to_owned())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    version: u8,
    boot: String,
    saved_ns: u64,
    records: Bounded<Row, LIMIT>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    query: SourceQuery,
    addresses: Bounded<IpAddr, MAX_ROUTE_ANSWER_ADDRESSES>,
    expires_ns: u64,
}

fn valid(query: &SourceQuery, addresses: &[IpAddr]) -> bool {
    matches!(query.kind, 1 | 28)
        && !query.client.is_unspecified()
        && !query.client.is_multicast()
        && query.client == query.client.to_canonical()
        && query
            .ingress
            .as_deref()
            .is_none_or(nfqws2_awg_rules::kernel::valid_dns_bridge)
        && query.name.len() <= 253
        && nfqws2_dns::build_query(&query.name, query.kind, 0)
            .and_then(|wire| nfqws2_dns::query_domain(&wire))
            .is_ok_and(|(name, _)| !name.is_empty() && name == query.name)
        && !addresses.is_empty()
        && addresses.len() <= MAX_ROUTE_ANSWER_ADDRESSES
        && addresses.iter().all(|ip| {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.is_ipv4() == (query.kind == 1)
                && *ip == ip.to_canonical()
        })
}

pub(super) fn snapshot(
    boot: &str,
    records: &BTreeMap<SourceQuery, Record>,
    clock: Clock,
) -> Envelope {
    let rows = records.iter().filter_map(|(query, record)| {
        if record.managed.is_some() {
            return None;
        }
        let remaining = record.expires.checked_duration_since(clock.instant)?;
        let ns = u64::try_from(remaining.as_nanos()).ok()?;
        if ns == 0 || ns > MAX_TTL_NS || !valid(query, &record.addresses) {
            return None;
        }
        Some(Row {
            query: query.clone(),
            addresses: Bounded(record.addresses.clone()),
            expires_ns: clock.ns.checked_add(ns)?,
        })
    });
    Envelope {
        version: 1,
        boot: boot.to_owned(),
        saved_ns: clock.ns,
        records: Bounded(rows.collect()),
    }
}

pub(super) fn write(tx: &Transaction<'_>, envelope: &Envelope) -> io::Result<()> {
    if envelope.records.0.is_empty() {
        tx.delete_runtime(FILE)
    } else {
        tx.save_runtime_bounded(FILE, envelope, FILE_LIMIT)
    }
}

pub(super) fn read(
    db: &Store,
    boot: &str,
    clock: Clock,
) -> io::Result<BTreeMap<SourceQuery, Record>> {
    let envelope: Envelope = db.read_runtime(FILE, FILE_LIMIT)?;
    if envelope.version != 1 || envelope.boot != boot || envelope.saved_ns > clock.ns {
        return Ok(BTreeMap::new());
    }
    let restored = envelope.records.0.into_iter().filter_map(|row| {
        let remaining = row.expires_ns.checked_sub(clock.ns)?;
        if remaining == 0
            || row.expires_ns.saturating_sub(envelope.saved_ns) > MAX_TTL_NS
            || !valid(&row.query, &row.addresses.0)
        {
            return None;
        }
        let expires = clock.instant.checked_add(Duration::from_nanos(remaining))?;
        Some((
            row.query,
            Record {
                addresses: row.addresses.0,
                expires,
                managed: None,
            },
        ))
    });
    Ok(restored.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsserver::routing::recent::Recent;
    use crate::dnsserver::routing::{
        tests::ReplayGate, DnsOrigin, Observer, RouteAnswer, RouteObserver,
    };
    use std::sync::{atomic::Ordering, Arc, Mutex};

    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const NEXT_BOOT: &str = "22222222-2222-4222-8222-222222222222";
    const NAME: &str = "host.office.test";

    fn origin(bridge: &'static str) -> DnsOrigin<'static> {
        DnsOrigin {
            client: Some(IpAddr::from([127, 0, 0, 1])),
            ingress: Some(bridge),
        }
    }

    fn answer(ip: u8, ttl: u32) -> RouteAnswer {
        RouteAnswer {
            qtype: 1,
            addresses: vec![IpAddr::from([192, 0, 2, ip])],
            ttl,
        }
    }

    fn clock(instant: Instant, seconds: u64) -> Clock {
        Clock {
            ns: seconds * 1_000_000_000,
            instant,
        }
    }

    #[tokio::test]
    async fn restored_recent_dns_replays_exact_scope_and_remaining_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let old_store = Store::open(dir.path()).unwrap();
        let start = Instant::now();
        let mut recent = Recent {
            boot: Some(BOOT.to_owned()),
            ..Recent::default()
        };
        recent.observe(NAME, origin("br-client"), answer(2, 10), start);
        recent.observe(NAME, origin("br-other"), answer(3, 10), start);
        recent.observe(
            "expired.office.test",
            origin("br-client"),
            answer(4, 2),
            start,
        );
        Recent::flush_at(&Mutex::new(recent), &old_store, || Ok(clock(start, 50))).unwrap();
        assert!(old_store.private_runtime_dir().join(FILE).is_file());

        let reopened = Store::open(dir.path()).unwrap();
        let restored = Recent::open_at(&reopened, BOOT.to_owned(), clock(start, 55));
        assert_eq!(restored.records.len(), 2);
        let new_boot = Recent::open_at(&reopened, NEXT_BOOT.to_owned(), clock(start, 55));
        assert!(new_boot.records.is_empty());
        let routes = Arc::new(Observer {
            recent: Mutex::new(restored),
            ..Observer::default()
        });
        let gate = Arc::new(ReplayGate::default());
        routes.register(gate.clone());
        let stale = gate.replay_publication().unwrap();
        gate.generation.store(1, Ordering::SeqCst);
        let current = gate.replay_publication().unwrap();
        assert_eq!(stale.revision, current.revision);
        routes.schedule_restored_replay(stale);
        assert!(routes.replay.lock().unwrap().is_none());

        let writer = routes.writer.clone().acquire_owned().await.unwrap();
        routes.schedule_restored_replay(current);
        tokio::time::timeout(Duration::from_secs(2), gate.selecting.notified())
            .await
            .unwrap();
        let stale_job = routes.replay.lock().unwrap().take().unwrap();
        gate.generation.store(2, Ordering::SeqCst);
        drop(writer);
        tokio::time::timeout(Duration::from_secs(2), stale_job)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.installs.lock().unwrap().is_empty());

        let current = gate.replay_publication().unwrap();
        routes.schedule_restored_replay(current);
        let job = routes.replay.lock().unwrap().take().unwrap();
        tokio::time::timeout(Duration::from_secs(2), job)
            .await
            .unwrap()
            .unwrap();
        routes.schedule_restored_replay(current);
        assert!(routes.replay.lock().unwrap().is_none());
        let installs = gate.installs.lock().unwrap();
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].addresses, [IpAddr::from([192, 0, 2, 2])]);
        assert!((1..=5).contains(&installs[0].ttl));
    }

    #[test]
    fn recent_dns_load_rejects_malformed_expiry_scope_and_array_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let start = Instant::now();
        let mut recent = Recent::default();
        recent.observe(NAME, origin("br-client"), answer(2, 20), start);
        let mut disk = snapshot(BOOT, &recent.records, clock(start, 50));
        assert_eq!(disk.records.0.len(), 1);
        store.transaction(|tx| write(tx, &disk)).unwrap();
        assert!(read(&store, BOOT, clock(start, 49)).unwrap().is_empty());
        assert!(read(&store, BOOT, clock(start, 70)).unwrap().is_empty());

        disk.records.0[0].expires_ns = u64::MAX;
        store.transaction(|tx| write(tx, &disk)).unwrap();
        assert!(read(&store, BOOT, clock(start, 55)).unwrap().is_empty());

        let mut disk = snapshot(BOOT, &recent.records, clock(start, 50));
        disk.records.0[0].query.ingress = Some("br-client/foreign".to_owned());
        store.transaction(|tx| write(tx, &disk)).unwrap();
        assert!(read(&store, BOOT, clock(start, 55)).unwrap().is_empty());

        let mut disk = snapshot(BOOT, &recent.records, clock(start, 50));
        disk.records.0[0].addresses.0 =
            vec![IpAddr::from([192, 0, 2, 2]); MAX_ROUTE_ANSWER_ADDRESSES + 1];
        store.transaction(|tx| write(tx, &disk)).unwrap();
        assert!(read(&store, BOOT, clock(start, 55)).is_err());
        assert!(Recent::open_at(&store, BOOT.to_owned(), clock(start, 55))
            .records
            .is_empty());
    }

    #[test]
    fn negative_dns_flush_removes_the_last_saved_positive() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let start = Instant::now();
        let mut recent = Recent {
            boot: Some(BOOT.to_owned()),
            ..Recent::default()
        };
        recent.observe(NAME, origin("br-client"), answer(2, 20), start);
        let cache = Mutex::new(recent);
        Recent::flush_at(&cache, &store, || Ok(clock(start, 50))).unwrap();
        let last = RouteAnswer {
            qtype: 1,
            addresses: Vec::new(),
            ttl: 0,
        };
        cache
            .lock()
            .unwrap()
            .observe(NAME, origin("br-client"), last, start);
        Recent::flush_at(&cache, &store, || Ok(clock(start, 51))).unwrap();
        assert!(!store.private_runtime_dir().join(FILE).exists());
        assert!(Recent::open_at(&store, BOOT.to_owned(), clock(start, 51))
            .records
            .is_empty());
    }

    #[tokio::test]
    async fn managed_recent_dns_answers_never_enter_the_restart_receipt() {
        use crate::dnsserver::{
            config,
            routing::ManagedRecent,
            runtime::{Diagnostics, Engine},
            shadow, vpn,
        };
        let engine = Engine::new(
            config::Config::from_value(&config::defaults()).unwrap(),
            Arc::new(Mutex::new(Diagnostics::new(false))),
            Default::default(),
            shadow::Environment::unavailable(),
            Arc::new(vpn::Source::with(|| Ok(Vec::new()))),
            Arc::new(Observer::default()),
        );
        let receipt = ManagedRecent::capture(&engine, None).unwrap();
        let now = Instant::now();
        let mut recent = Recent {
            boot: Some(BOOT.to_owned()),
            ..Recent::default()
        };
        recent.observe_from(
            "internal-ready.office.test",
            DnsOrigin {
                client: Some(IpAddr::from([192, 168, 1, 9])),
                ingress: None,
            },
            answer(9, 42),
            now,
            Some(receipt),
        );
        assert_eq!(recent.records.len(), 1);
        assert!(!recent.pending());
        recent.observe(NAME, origin("br-client"), answer(2, 20), now);
        let disk = snapshot(BOOT, &recent.records, clock(now, 50));
        assert_eq!(disk.records.0.len(), 1);
        assert_eq!(disk.records.0[0].query.name, NAME);
        assert_eq!(recent.records.len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recent_dns_bootstrap_uses_the_linux_monotonic_clock() {
        let dir = tempfile::tempdir().unwrap();
        let boot_path = dir.path().join("proc/sys/kernel/random/boot_id");
        std::fs::create_dir_all(boot_path.parent().unwrap()).unwrap();
        std::fs::write(&boot_path, format!("{BOOT}\n")).unwrap();
        let db = Store::open(dir.path().join("data")).unwrap();
        let now = Instant::now();
        let mut before = Recent::open(&db, dir.path());
        before.observe(NAME, origin("br-client"), answer(2, 30), now);
        Recent::flush(&Mutex::new(before), &db).unwrap();

        let restored = Recent::open(&db, dir.path());
        assert!(restored.has_restored());
        assert_eq!(restored.records.len(), 1);
        let record = restored.records.values().next().unwrap();
        assert!(record.expires <= now + Duration::from_secs(30));
        assert!(record.expires > now);
        std::fs::write(&boot_path, format!("{NEXT_BOOT}\n")).unwrap();
        assert!(!Recent::open(&db, dir.path()).has_restored());
    }
}
