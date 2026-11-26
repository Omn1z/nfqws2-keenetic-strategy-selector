use super::{DnsOrigin, FailedRoute, ManagedRecent, RouteAnswer};
use nfqws2_store::Store;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io, net::IpAddr, path::Path, sync::Mutex};
use tokio::time::Instant;

mod persist;
const LIMIT: usize = 4096;

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceQuery {
    pub(super) name: String,
    pub(super) client: IpAddr,
    pub(super) ingress: Option<String>,
    pub(super) kind: u16,
}

impl SourceQuery {
    pub(super) fn origin(&self) -> DnsOrigin<'_> {
        DnsOrigin {
            client: Some(self.client),
            ingress: self.ingress.as_deref(),
        }
    }
}

#[derive(Clone)]
pub(super) struct Record {
    pub(super) addresses: Vec<IpAddr>,
    pub(super) expires: Instant,
    pub(super) managed: Option<ManagedRecent>,
}

impl Record {
    pub(super) fn failure(&self) -> Option<FailedRoute> {
        self.managed.as_ref()?.failure
    }
}

#[derive(Default)]
pub(super) struct Recent {
    records: BTreeMap<SourceQuery, Record>,
    boot: Option<String>,
    sequence: u64,
    flushed: u64,
    restored: bool,
}

impl Recent {
    pub(super) fn open(db: &Store, root: &Path) -> Self {
        let Some(boot) = persist::boot_id(root) else {
            return Self::default();
        };
        let Ok(clock) = persist::Clock::for_load() else {
            return Self::default();
        };
        Self::open_at(db, boot, clock)
    }

    fn open_at(db: &Store, boot: String, clock: persist::Clock) -> Self {
        let records = persist::read(db, &boot, clock).unwrap_or_default();
        Self {
            restored: !records.is_empty(),
            records,
            boot: Some(boot),
            ..Self::default()
        }
    }

    pub(super) fn has_restored(&self) -> bool {
        self.restored
    }

    pub(super) fn finish_restored(&mut self) {
        self.restored = false;
    }

    pub(super) fn has_failed_replies(&self, now: Instant) -> bool {
        self.records
            .values()
            .any(|record| record.expires > now && record.failure().is_some())
    }

    pub(super) fn retire_failed(
        &mut self,
        query: &SourceQuery,
        failure: FailedRoute,
        expires: Instant,
    ) {
        if self
            .records
            .get(query)
            .is_some_and(|record| record.expires == expires && record.failure() == Some(failure))
        {
            self.records.remove(query);
        }
    }

    pub(super) fn flush(cache: &Mutex<Self>, db: &Store) -> io::Result<()> {
        Self::flush_at(cache, db, persist::Clock::for_save)
    }

    fn flush_at(
        cache: &Mutex<Self>,
        db: &Store,
        clock: impl FnOnce() -> io::Result<persist::Clock>,
    ) -> io::Result<()> {
        let lock = || {
            cache
                .lock()
                .map_err(|_| io::Error::other("DNS replay cache unavailable"))
        };
        if !lock()?.pending() {
            return Ok(());
        }
        db.transaction(|tx| {
            let (sequence, disk) = {
                let state = lock()?;
                let Some(boot) = state.boot.as_deref().filter(|_| state.pending()) else {
                    return Ok(());
                };
                (
                    state.sequence,
                    persist::snapshot(boot, &state.records, clock()?),
                )
            };
            persist::write(tx, &disk)?;
            lock()?.flushed = sequence;
            Ok(())
        })
    }

    fn pending(&self) -> bool {
        self.boot.is_some() && self.sequence != self.flushed
    }

    pub(super) fn observe(
        &mut self,
        name: &str,
        origin: DnsOrigin<'_>,
        answer: RouteAnswer,
        now: Instant,
    ) {
        self.observe_from(name, origin, answer, now, None);
    }

    pub(super) fn observe_from(
        &mut self,
        name: &str,
        origin: DnsOrigin<'_>,
        mut answer: RouteAnswer,
        ttl_anchor: Instant,
        managed: Option<ManagedRecent>,
    ) {
        let Some(client) = origin.client else { return };
        if !matches!(answer.qtype, 1 | 28) {
            return;
        }
        let query = SourceQuery {
            name: name.to_owned(),
            client,
            ingress: origin.ingress.map(str::to_owned),
            kind: answer.qtype,
        };
        let mut dirty = self
            .records
            .remove(&query)
            .is_some_and(|record| record.managed.is_none());
        answer
            .addresses
            .retain(|ip| ip.is_ipv4() == (answer.qtype == 1));
        let expires = ttl_anchor + std::time::Duration::from_secs(answer.ttl.into());
        if answer.ttl == 0 || answer.addresses.is_empty() || expires <= Instant::now() {
            if dirty {
                self.sequence = self.sequence.wrapping_add(1);
            }
            return;
        }
        if self.records.len() == LIMIT {
            let oldest = self
                .records
                .iter()
                .min_by_key(|(_, record)| record.expires)
                .map(|(query, _)| query.clone())
                .expect("full DNS replay cache");
            dirty |= self
                .records
                .remove(&oldest)
                .is_some_and(|record| record.managed.is_none());
        }
        dirty |= managed.is_none();
        self.records.insert(
            query,
            Record {
                addresses: answer.addresses,
                expires,
                managed,
            },
        );
        if dirty {
            self.sequence = self.sequence.wrapping_add(1);
        }
    }

    pub(super) fn snapshot(&mut self, now: Instant) -> Vec<(SourceQuery, Record)> {
        self.records.retain(|_, record| record.expires > now);
        let mut records: Vec<_> = self
            .records
            .iter()
            .map(|(query, record)| (query.clone(), record.clone()))
            .collect();
        records.sort_by_key(|(_, record)| std::cmp::Reverse(record.expires));
        records
    }
}
