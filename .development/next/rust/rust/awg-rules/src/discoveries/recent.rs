//! Current DNS confirmations and batched observations in Go's wire format.
use super::{load_groups, trim, Entry, HashMap, IpAddr, FILE, LIMIT, RULE_LIMIT};
use nfqws2_store::{Store, Transaction};
use serde::Serialize;
use std::{io, sync::Mutex, time::Instant};

#[derive(Clone)]
struct Address {
    ip: IpAddr,
    epoch: u64,
    revision: u64,
    at: Instant,
}
#[derive(Clone)]
struct Seen {
    first: i64,
    last: i64,
    at: Instant,
    additional: bool,
    ips: Vec<Address>,
    clients: Vec<IpAddr>,
}
#[derive(Default)]
struct State {
    rules: HashMap<String, HashMap<String, Seen>>,
    count: usize,
    epoch: u64,
    sequence: u64,
    flushed: u64,
}
#[derive(Default)]
pub struct Recent(Mutex<State>);
impl Recent {
    pub fn invalidate(&self) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.epoch = state.epoch.wrapping_add(1);
    }
    pub fn reset_after_restore(&self) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *state = State {
            epoch: state.epoch.wrapping_add(1),
            ..Default::default()
        };
    }
    /// Return a bounded copy of observed names for fresh resolution. An
    /// invalidated confirmation still supplies a name to the next policy.
    pub fn archive_names(&self) -> Vec<(String, i64)> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state
            .rules
            .values()
            .flat_map(|rows| rows.iter())
            .filter(|(_, seen)| seen.last > 0 && !seen.ips.is_empty())
            .map(|(name, seen)| (name.clone(), seen.last))
            .collect()
    }
    pub fn flush(&self, db: &Store) -> io::Result<()> {
        if !self.pending() {
            return Ok(());
        }
        db.transaction(|tx| self.flush_locked(db, tx))
    }
    fn pending(&self) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.sequence != state.flushed
    }
    pub fn flush_locked(&self, db: &Store, tx: &Transaction<'_>) -> io::Result<()> {
        if !self.pending() {
            return Ok(());
        }
        let mut groups = load_groups(db)?;
        let seq = self.merge(&mut groups, false, 0);
        trim(&mut groups);
        #[derive(Serialize)]
        struct Record<'a> {
            rule_key: &'a str,
            domain: &'a str,
            ips: &'a [String],
            source_ips: &'a [String],
            source: &'a str,
            first_seen: i64,
            last_seen: i64,
            additional: bool,
        }
        #[derive(Serialize)]
        struct DiskHistory<'a> {
            version: u8,
            entries: Vec<Record<'a>>,
        }
        let mut entries = groups
            .iter()
            .flat_map(|(key, rows)| {
                rows.iter().map(move |row| Record {
                    rule_key: key,
                    domain: &row.domain,
                    ips: &row.ips,
                    source_ips: row.source_ips.as_deref().unwrap_or_default(),
                    source: &row.source,
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                    additional: row.additional,
                })
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| (a.rule_key, a.domain).cmp(&(b.rule_key, b.domain)));
        tx.save(
            FILE,
            &DiskHistory {
                version: 1,
                entries,
            },
        )?;
        self.0.lock().unwrap_or_else(|e| e.into_inner()).flushed = seq;
        Ok(())
    }
    pub fn confirm(
        &self,
        revision: u64,
        rule: (&str, bool),
        name: &str,
        client: Option<IpAddr>,
        ips: &[IpAddr],
    ) {
        let (key, additional) = rule;
        if key.len() != 64
            || name.is_empty()
            || name.len() > 253
            || ips
                .iter()
                .take(64)
                .all(|ip| ip.to_canonical().is_unspecified())
        {
            return;
        }
        // A simultaneous history read must not delay a routed DNS response.
        let Ok(mut state) = self.0.try_lock() else {
            return;
        };
        let at = Instant::now();
        let when = nfqws2_awg_profile::now() as i64;
        let epoch = state.epoch;
        if !state.rules.get(key).is_some_and(|r| r.contains_key(name)) {
            if let Some(rows) = state
                .rules
                .get_mut(key)
                .filter(|rows| rows.len() == RULE_LIMIT)
            {
                let evicted = rows
                    .iter()
                    .min_by_key(|(_, seen)| seen.at)
                    .map(|(name, _)| name.clone())
                    .expect("full history rule");
                rows.remove(&evicted);
                state.count -= 1;
            } else if state.count == LIMIT {
                let Some((rule, domain, _)) = state
                    .rules
                    .iter()
                    .flat_map(|(rule, rows)| {
                        rows.iter().map(move |(domain, s)| (rule, domain, s.at))
                    })
                    .min_by_key(|(_, _, time)| *time)
                else {
                    return;
                };
                let (rule, domain) = (rule.clone(), domain.clone());
                let rows = state.rules.get_mut(&rule).unwrap();
                rows.remove(&domain);
                if rows.is_empty() {
                    state.rules.remove(&rule);
                }
                state.count -= 1;
            }
            state.rules.entry(key.to_owned()).or_default().insert(
                name.to_owned(),
                Seen {
                    first: when,
                    last: when,
                    at,
                    additional,
                    ips: Vec::new(),
                    clients: Vec::new(),
                },
            );
            state.count += 1;
        }
        let row = state.rules.get_mut(key).unwrap().get_mut(name).unwrap();
        row.last = when.max(row.last);
        row.at = at;
        row.additional = additional;
        for ip in ips
            .iter()
            .take(64)
            .map(|v| v.to_canonical())
            .filter(|ip| !ip.is_unspecified())
        {
            let value = Address {
                ip,
                epoch,
                revision,
                at,
            };
            if let Some(prior) = row.ips.iter_mut().find(|a| a.ip == ip) {
                *prior = value;
            } else if row.ips.len() < 64 {
                row.ips.push(value);
            } else if let Some(oldest) = row.ips.iter_mut().min_by_key(|a| a.at) {
                *oldest = value;
            }
        }
        if let Some(ip) = client
            .map(|a| a.to_canonical())
            .filter(|a| !a.is_unspecified())
        {
            if let Some(pos) = row.clients.iter().position(|a| a == &ip) {
                row.clients.remove(pos);
            } else if row.clients.len() == 8 {
                row.clients.remove(0);
            }
            row.clients.push(ip);
        }
        state.sequence = state.sequence.wrapping_add(1);
    }
    pub(super) fn merge(
        &self,
        grouped: &mut HashMap<String, Vec<Entry>>,
        ready: bool,
        revision: u64,
    ) -> u64 {
        let (rules, epoch, sequence) = {
            let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            (state.rules.clone(), state.epoch, state.sequence)
        };
        for (rule, rows) in &rules {
            let entries = grouped.entry(rule.clone()).or_default();
            for (domain, seen) in rows {
                if seen.ips.is_empty() {
                    continue;
                }
                let mut ips: Vec<_> = seen.ips.iter().map(|a| a.ip.to_string()).collect();
                let mut clients: Vec<_> = seen.clients.iter().map(ToString::to_string).collect();
                let mut confirmed = ready
                    && seen
                        .ips
                        .iter()
                        .all(|a| a.epoch == epoch && a.revision == revision);
                let mut first = seen.first;
                let mut last = seen.last;
                let mut source = "dns".to_owned();
                let mut additional = seen.additional;
                if let Some(index) = entries.iter().position(|e| &e.domain == domain) {
                    let old = entries.swap_remove(index);
                    if old.last_seen > last {
                        last = old.last_seen;
                        source = old.source;
                        additional = old.additional;
                    }
                    first = first.min(old.first_seen);
                    for ip in old.ips {
                        if ips.len() < 64 && !ips.contains(&ip) {
                            ips.push(ip);
                            confirmed = false;
                        }
                    }
                    for client in old.source_ips.unwrap_or_default() {
                        if clients.len() < 8 && !clients.contains(&client) {
                            clients.push(client);
                        }
                    }
                }
                clients.sort_unstable();
                ips.sort_unstable();
                entries.push(Entry {
                    rule_key: String::new(),
                    domain: domain.clone(),
                    ips,
                    source_ips: Some(clients),
                    source,
                    first_seen: first,
                    last_seen: last,
                    additional,
                    confirmed,
                });
            }
        }
        sequence
    }
}
