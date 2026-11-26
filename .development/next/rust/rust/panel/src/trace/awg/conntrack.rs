use super::{ptr, Flow, FlowRoute, Job, Service, CAP};
use nfqws2_monitor::{Conn, NetworkMonitor};
use nfqws2_store::Store;
use std::{
    collections::{HashSet, VecDeque},
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::oneshot,
    time::{interval, MissedTickBehavior},
};

mod decision;
mod state;

use decision::{Decision, Decisions};

const POLL: Duration = Duration::from_secs(1);
const POLICY_TTL: Duration = Duration::from_secs(5);
const MAX_ROWS: usize = 32_768;
const MAX_SCANNED: usize = 262_144;

#[derive(Default)]
pub(super) struct Source(Option<PathBuf>);

impl Source {
    pub(super) fn new(root: &Path) -> Self {
        Self(Some(root.to_owned()))
    }

    pub(super) fn available(&self) -> bool {
        self.0.as_ref().is_some_and(|root| {
            NetworkMonitor::new(root.join("proc"), root)
                .connection_reader()
                .is_ok()
        })
    }
}

struct Rules {
    stamp: Option<(u64, SystemTime)>,
    until: Instant,
    generation: u64,
    decisions: Decisions,
}

struct Sampler {
    monitor: NetworkMonitor,
    boot_path: PathBuf,
    document: PathBuf,
    db: Store,
    rules: Option<Rules>,
    tracker: state::Tracker<Decision>,
}

struct Observed {
    flow: Flow,
    route: FlowRoute,
    detail: &'static str,
}

struct Batch {
    entries: VecDeque<Observed>,
    limited: bool,
    generation: u64,
}

fn rows(monitor: &NetworkMonitor) -> io::Result<(Vec<Conn>, bool)> {
    let mut rows = Vec::new();
    let mut unique = HashSet::new();
    let mut scanned = 0;
    let mut complete = true;
    let result = monitor.connection_reader()?.visit(|mut row| {
        scanned += 1;
        if scanned > MAX_SCANNED {
            complete = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some(key) = state::Key::of(&row) {
            if !unique.insert(key) {
                return Ok(());
            }
            if rows.len() == MAX_ROWS {
                complete = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            row.mac = String::new();
            rows.push(row);
        }
        Ok(())
    });
    if complete {
        result?;
    }
    Ok((rows, complete))
}

impl Sampler {
    fn sample(&mut self) -> io::Result<Batch> {
        let now = Instant::now();
        let stamp = fs::metadata(&self.document)
            .ok()
            .and_then(|v| v.modified().ok().map(|t| (v.len(), t)));
        if self
            .rules
            .as_ref()
            .is_none_or(|old| old.until <= now || old.stamp != stamp)
        {
            let boot = fs::read_to_string(&self.boot_path)?;
            self.rules = Some(Rules {
                stamp,
                until: now + POLICY_TTL,
                generation: self
                    .rules
                    .as_ref()
                    .map_or(0, |old| old.generation.wrapping_add(1)),
                decisions: Decisions::read(&self.db, boot.trim())?,
            });
        }
        let rules = self.rules.as_ref().unwrap();
        let (rows, complete) = rows(&self.monitor)?;
        let mut batch = Batch {
            entries: VecDeque::new(),
            limited: !complete,
            generation: rules.generation,
        };
        self.tracker.update(
            now,
            complete,
            rules.generation,
            rows,
            |conn| {
                let (src, dst) = conn.src.zip(conn.dst)?;
                let decision = rules.decisions.classify(src, dst);
                (decision.kind != "unknown").then_some(decision)
            },
            |event, conn, decision| {
                if batch.entries.len() == CAP {
                    batch.entries.pop_front();
                    batch.limited = true;
                }
                batch.entries.push_back(Observed {
                    flow: Flow {
                        src: conn.src.expect("tracked original source"),
                        dst: conn.dst.expect("tracked original destination"),
                        proto: conn.proto.to_string(),
                        sport: conn.sport.try_into().unwrap_or(0),
                        dport: conn.dport.try_into().unwrap_or(0),
                        event: event.as_str().into(),
                        packets: conn.packets,
                        bytes: conn.bytes,
                        reply_bytes: conn.reply_bytes,
                        state: conn.state.to_string(),
                        unreplied: conn.unreplied,
                        assured: conn.assured,
                    },
                    route: FlowRoute {
                        decision: decision.kind,
                        rule: decision.rule,
                        reason: decision.reason.clone(),
                        tunnel_id: decision.tunnel_id.clone(),
                        tunnel_iface: decision.tunnel_iface.clone(),
                    },
                    detail: event.reason(conn),
                });
            },
        );
        Ok(batch)
    }
}

pub(super) fn start(service: &Service, db: Store, data_dir: &Path) -> Job {
    let root = service
        .conntrack
        .0
        .as_ref()
        .expect("configured conntrack source");
    let proc = root.join("proc");
    let mut sampler = Sampler {
        monitor: NetworkMonitor::new(&proc, root),
        boot_path: proc.join("sys/kernel/random/boot_id"),
        document: data_dir.join("awg.json"),
        db,
        rules: None,
        tracker: state::Tracker::default(),
    };
    let ring = service.ring.clone();
    let mut reverse = ptr::Queue::new(service.resolver.clone());
    let (stop, mut stopped) = oneshot::channel();
    {
        let mut state = ring.lock().unwrap();
        state.conntrack = true;
        state.limited = false;
        state.observed = 0;
    }
    let task = tokio::spawn(async move {
        let mut ticker = interval(POLL);
        let mut generation = 0;
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => break,
                answer = reverse.next(), if !reverse.is_empty() => {
                    if let Some(answer) = answer {
                        ring.lock().unwrap().resolved(answer, generation);
                    }
                }
                _ = ticker.tick() => {
                    let sample = tokio::task::spawn_blocking(move || {
                        let result = sampler.sample();
                        (sampler, result)
                    }).await;
                    if !matches!(stopped.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
                        break;
                    }
                    let mut ring = ring.lock().unwrap();
                    let Ok((next, outcome)) = sample else {
                        ring.error = "Не удалось прочитать потоки conntrack".into();
                        break;
                    };
                    sampler = next;
                    match outcome {
                        Ok(batch) => {
                            generation = batch.generation;
                            ring.error.clear();
                            ring.limited = batch.limited;
                            for row in batch.entries {
                                if let Some(request) = ring.flow(row.flow, row.route, row.detail) {
                                    reverse.request(&mut ring, request, generation);
                                }
                            }
                        }
                        Err(error) => {
                            ring.error = format!("Не удалось прочитать потоки conntrack ({:?})", error.kind());
                        }
                    }
                }
            }
        }
        ring.lock().unwrap().recording = false;
    });
    Job { stop, task }
}
