//! Lightweight router-wide dashboard measurements from Linux procfs.
//! Keep one sampler per procfs mount to share CPU deltas and the refresh interval.

#[cfg(test)]
mod tests;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MIN_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CPU_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SystemStats {
    /// -1 until two valid samples are available within the last 30 seconds.
    pub cpu_percent: f64,
    pub load_avg: [f64; 3],
    pub uptime_sec: u64,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub memory: MemoryStats,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MemoryStats {
    pub mem_total_kb: u64,
    pub mem_free_kb: u64,
    pub mem_avail_kb: u64,
    pub mem_used_kb: u64,
    pub mem_kernel_kb: u64,
    pub mem_cache_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

impl SystemStats {
    /// Writes the router-wide subset of the existing dashboard JSON fields.
    pub fn write_json(&self, out: &mut impl Write) -> io::Result<()> {
        let [one, five, fifteen] = self.load_avg;
        let m = &self.memory;
        write!(
            out,
            concat!(
            "{{\"cpu_percent\":{},\"load_avg\":[{},{},{}],\"uptime_sec\":{},",
            "\"mem_total_kb\":{},\"mem_free_kb\":{},\"mem_avail_kb\":{},\"mem_used_kb\":{},",
            "\"mem_kernel_kb\":{},\"mem_cache_kb\":{},\"swap_total_kb\":{},\"swap_free_kb\":{}}}"
        ),
            self.cpu_percent,
            one,
            five,
            fifteen,
            self.uptime_sec,
            m.mem_total_kb,
            m.mem_free_kb,
            m.mem_avail_kb,
            m.mem_used_kb,
            m.mem_kernel_kb,
            m.mem_cache_kb,
            m.swap_total_kb,
            m.swap_free_kb
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CpuTicks {
    total: i64,
    idle: i64,
}

impl CpuTicks {
    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_ascii_whitespace();
        if fields.next()? != "cpu" {
            return None;
        }
        let mut ticks = Self::default();
        let mut count = 0;
        // Linux already includes guest/guest_nice in user/nice.
        for (i, field) in fields.take(8).enumerate() {
            let value: i64 = field.parse().ok()?;
            if value < 0 {
                return None;
            }
            ticks.total = ticks.total.checked_add(value)?;
            if i == 3 || i == 4 {
                ticks.idle += value;
            }
            count += 1;
        }
        (count >= 4).then_some(ticks)
    }

    fn percent_since(self, prev: Self, elapsed: Duration) -> f64 {
        if elapsed.is_zero()
            || elapsed > MAX_CPU_INTERVAL
            || self.idle < prev.idle
            || self.total <= prev.total
        {
            return -1.0;
        }
        let total = self.total - prev.total;
        let idle = self.idle - prev.idle;
        100.0 * (total - idle).max(0) as f64 / total as f64
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl MemoryStats {
    fn parse(text: &str) -> io::Result<Self> {
        let mut stats = Self::default();
        let (mut buffers, mut cached, mut reclaimable, mut shmem): (u64, u64, u64, u64) =
            (0, 0, 0, 0);
        for line in text.lines() {
            let Some((key, rest)) = line.split_once(':') else {
                continue;
            };
            let field = match key {
                "MemTotal" => &mut stats.mem_total_kb,
                "MemFree" => &mut stats.mem_free_kb,
                "MemAvailable" => &mut stats.mem_avail_kb,
                "SUnreclaim" => &mut stats.mem_kernel_kb,
                "SwapTotal" => &mut stats.swap_total_kb,
                "SwapFree" => &mut stats.swap_free_kb,
                "Buffers" => &mut buffers,
                "Cached" => &mut cached,
                "SReclaimable" => &mut reclaimable,
                "Shmem" => &mut shmem,
                _ => continue,
            };
            *field = rest
                .split_ascii_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| invalid("invalid counter in meminfo"))?;
        }
        if stats.mem_total_kb == 0 {
            return Err(invalid("missing or zero MemTotal in meminfo"));
        }
        stats.mem_cache_kb = buffers
            .checked_add(cached)
            .and_then(|v| v.checked_add(reclaimable))
            .ok_or_else(|| invalid("meminfo cache counter overflow"))?
            .saturating_sub(shmem);
        stats.mem_used_kb = stats
            .mem_total_kb
            .saturating_sub(stats.mem_free_kb)
            .saturating_sub(stats.mem_cache_kb);
        Ok(stats)
    }
}

fn parse_load(text: &str) -> io::Result<[f64; 3]> {
    let mut values = text.split_ascii_whitespace();
    let mut load = [0.0; 3];
    for field in &mut load {
        *field = values
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or_else(|| invalid("invalid loadavg"))?;
    }
    Ok(load)
}

fn parse_uptime(text: &str) -> io::Result<u64> {
    let field = text.split_ascii_whitespace().next().unwrap_or_default();
    let (whole, fraction) = field.split_once('.').unwrap_or((field, ""));
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid uptime"));
    }
    whole.parse().map_err(|_| invalid("invalid uptime"))
}

pub struct SystemSampler {
    proc_root: PathBuf,
    scratch: String,
    last_cpu: Option<(Instant, CpuTicks)>,
    cached: Option<(Instant, SystemStats)>,
}

impl SystemSampler {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            scratch: String::with_capacity(2048),
            last_cpu: None,
            cached: None,
        }
    }

    pub fn snapshot(&mut self) -> io::Result<SystemStats> {
        self.snapshot_with(Instant::now)
    }

    /// Fresh per-file measurements for the dashboard, which caches the entire
    /// snapshot (including process and thermal data) outside this sampler.
    pub fn sample_best_effort(&mut self) -> SystemStats {
        let memory = self
            .read_file("meminfo")
            .and_then(MemoryStats::parse)
            .unwrap_or_default();
        let load_avg = self
            .read_file("loadavg")
            .and_then(parse_load)
            .unwrap_or_default();
        let uptime_sec = self
            .read_file("uptime")
            .and_then(parse_uptime)
            .unwrap_or_default();
        let cpu_percent = self.read_cpu(Instant::now).unwrap_or(-1.0);
        SystemStats {
            memory,
            load_avg,
            uptime_sec,
            cpu_percent,
        }
    }

    fn snapshot_with(&mut self, now: impl Fn() -> Instant) -> io::Result<SystemStats> {
        let at = now();
        if let Some((sampled_at, stats)) = self.cached {
            if at
                .checked_duration_since(sampled_at)
                .is_some_and(|age| age < MIN_INTERVAL)
            {
                return Ok(stats);
            }
        }
        let memory = MemoryStats::parse(self.read_file("meminfo")?)?;
        let load_avg = parse_load(self.read_file("loadavg")?)?;
        let uptime_sec = parse_uptime(self.read_file("uptime")?)?;
        let cpu_percent = self.read_cpu(&now)?;
        let stats = SystemStats {
            cpu_percent,
            load_avg,
            uptime_sec,
            memory,
        };
        self.cached = Some((now(), stats));
        Ok(stats)
    }

    fn read_cpu(&mut self, now: impl Fn() -> Instant) -> io::Result<f64> {
        self.scratch.clear();
        let stat = File::open(self.proc_root.join("stat"))?;
        // Only the first line is used. The rest can grow with the number of CPUs and interrupts.
        BufReader::with_capacity(512, stat).read_line(&mut self.scratch)?;
        let current = CpuTicks::parse(&self.scratch)
            .ok_or_else(|| invalid("invalid aggregate CPU counters in stat"))?;
        let sampled_at = now();
        let cpu_percent = self.last_cpu.map_or(-1.0, |(ts, prev)| {
            current.percent_since(prev, sampled_at.saturating_duration_since(ts))
        });
        self.last_cpu = Some((sampled_at, current));
        Ok(cpu_percent)
    }

    fn read_file(&mut self, name: &str) -> io::Result<&str> {
        self.scratch.clear();
        File::open(self.proc_root.join(name))?.read_to_string(&mut self.scratch)?;
        Ok(&self.scratch)
    }
}
