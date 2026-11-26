use nfqws2_core::{SystemSampler, SystemStats};
use serde::Serialize;
#[cfg(test)]
#[path = "system_tests.rs"]
mod tests;
use std::{
    cmp::Reverse,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
pub struct SystemInfo {
    #[serde(flatten)]
    pub system: SystemStats,
    pub mem_apps_kb: u64,
    pub temps: Option<Vec<TempZone>>,
    pub services: Option<Vec<ServiceStat>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ServiceStat {
    pub name: String,
    pub pid: u32,
    pub cpu_percent: f64,
    pub rss_kb: u64,
    pub uptime_sec: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TempZone {
    pub label: String,
    pub c: i64,
}

struct ProcessCpu {
    ticks: u64,
    start: u64,
    at: Instant,
    live: bool,
}

fn process_percent(prev: &ProcessCpu, ticks: u64, start: u64, at: Instant) -> f64 {
    let elapsed = at.saturating_duration_since(prev.at);
    if start != prev.start
        || ticks < prev.ticks
        || elapsed.is_zero()
        || elapsed > Duration::from_secs(30)
    {
        return -1.0;
    }
    // The engine and Go panel use Linux USER_HZ=100. 100 ticks/s is one full core.
    (ticks - prev.ticks) as f64 / elapsed.as_secs_f64()
}

// /proc/PID/stat's comm may contain whitespace, ')' and newlines. All later
// offsets are relative to its final closing parenthesis.
fn parse_stat(text: &str) -> Option<(&str, u64, u64)> {
    let (head, fields) = text.rsplit_once(')')?;
    let (_, name) = head.split_once('(')?;
    let mut fields = fields.split_ascii_whitespace();
    let utime: u64 = fields.nth(11)?.parse().unwrap_or(0);
    let stime: u64 = fields.next()?.parse().unwrap_or(0);
    let start = fields.nth(6)?.parse().ok()?;
    fields.nth(1)?;
    Some((name, utime.saturating_add(stime), start))
}

pub struct Monitor {
    proc_root: PathBuf,
    thermal_root: PathBuf,
    core: SystemSampler,
    last: HashMap<u32, ProcessCpu>,
    cached: Option<(Instant, SystemInfo)>,
    page_kb: u64,
}

impl Monitor {
    pub fn new(proc_root: impl Into<PathBuf>, thermal_root: impl Into<PathBuf>) -> Self {
        let proc_root = proc_root.into();
        Self {
            core: SystemSampler::new(&proc_root),
            proc_root,
            thermal_root: thermal_root.into(),
            last: HashMap::new(),
            cached: None,
            page_kb: page_kb(),
        }
    }

    pub fn snapshot(&mut self) -> SystemInfo {
        self.snapshot_with(Instant::now)
    }

    fn snapshot_with(&mut self, now: impl Fn() -> Instant) -> SystemInfo {
        let at = now();
        if let Some((ts, cached)) = &self.cached {
            if at
                .checked_duration_since(*ts)
                .is_some_and(|elapsed| elapsed < Duration::from_secs(1))
            {
                return cached.clone();
            }
        }
        let system = self.core.sample_best_effort();
        let (services, mem_apps_kb) = self.processes(system.uptime_sec, at);
        let info = SystemInfo {
            system,
            mem_apps_kb,
            services,
            temps: temperatures(&self.thermal_root),
        };
        self.cached = Some((now(), info.clone()));
        info
    }

    fn processes(&mut self, uptime_sec: u64, now: Instant) -> (Option<Vec<ServiceStat>>, u64) {
        let Ok(dirs) = fs::read_dir(&self.proc_root) else {
            return (None, 0);
        };
        for prev in self.last.values_mut() {
            prev.live = false;
        }
        let mut total: u64 = 0;
        // The source API keeps the top ten by RSS; equal sizes follow lexical
        // directory order as with Go's os.ReadDir and stable sort.
        let mut top: Vec<(String, ServiceStat)> = Vec::with_capacity(10);
        for dir in dirs.flatten() {
            let Ok(id) = dir.file_name().into_string() else {
                continue;
            };
            let Ok(pid) = id.parse::<u32>() else { continue };
            if !dir.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            if let Some(prev) = self.last.get_mut(&pid) {
                prev.live = true;
            }
            let path = dir.path();
            let Ok(bytes) = fs::read(path.join("stat")) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            let Some((name, ticks, start)) = parse_stat(&text) else {
                continue;
            };
            let rss_kb = fs::read_to_string(path.join("statm"))
                .ok()
                .and_then(|s| s.split_ascii_whitespace().nth(1)?.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(self.page_kb);
            total = total.saturating_add(rss_kb);
            if rss_kb < 1024 {
                continue;
            }
            let prev = self.last.insert(
                pid,
                ProcessCpu {
                    ticks,
                    start,
                    at: now,
                    live: true,
                },
            );
            let at = top.partition_point(|(other_id, stat)| {
                stat.rss_kb > rss_kb || (stat.rss_kb == rss_kb && other_id <= &id)
            });
            if at == 10 {
                continue;
            }
            if top.len() == 10 {
                top.pop();
            }
            top.insert(
                at,
                (
                    id,
                    ServiceStat {
                        name: name.to_owned(),
                        pid,
                        cpu_percent: prev
                            .as_ref()
                            .map_or(-1.0, |sample| process_percent(sample, ticks, start, now)),
                        rss_kb,
                        uptime_sec: uptime_sec.saturating_sub(start / 100),
                    },
                ),
            );
        }
        self.last.retain(|_, sample| sample.live);
        (Some(top.into_iter().map(|(_, stat)| stat).collect()), total)
    }
}

fn page_kb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // sysconf requires no pointer arguments and returns -1 on error.
        let bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if bytes >= 1024 {
            return bytes as u64 / 1024;
        }
    }
    4
}

fn temperatures(root: &Path) -> Option<Vec<TempZone>> {
    let dirs = fs::read_dir(root).ok()?;
    let mut top: Vec<(String, TempZone)> = Vec::with_capacity(8);
    for dir in dirs.flatten() {
        let Ok(id) = dir.file_name().into_string() else {
            continue;
        };
        if !id.starts_with("thermal_zone") {
            continue;
        }
        let Ok(value) = fs::read_to_string(dir.path().join("temp")) else {
            continue;
        };
        let mut c = value.trim().parse::<i64>().unwrap_or(0);
        if c >= 1000 {
            c /= 1000;
        }
        let at = top.partition_point(|(other_id, t)| (Reverse(t.c), other_id) <= (Reverse(c), &id));
        if at == 8 {
            continue;
        }
        if top.len() == 8 {
            top.pop();
        }
        let label = fs::read_to_string(dir.path().join("type"))
            .map(|label| label.trim().to_owned())
            .unwrap_or_else(|_| id.clone());
        top.insert(at, (id, TempZone { label, c }));
    }
    (!top.is_empty()).then(|| top.into_iter().map(|(_, zone)| zone).collect())
}
