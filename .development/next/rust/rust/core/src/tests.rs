use super::*;
use std::cell::Cell;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
}

#[test]
fn sample_reads_router_wide_dashboard_fields() {
    let stats = SystemSampler::new(fixture()).snapshot().unwrap();
    let mut json = Vec::new();
    stats.write_json(&mut json).unwrap();
    assert_eq!(String::from_utf8(json).unwrap(), concat!(
        "{\"cpu_percent\":-1,\"load_avg\":[0.25,0.5,0.75],\"uptime_sec\":23456,",
        "\"mem_total_kb\":126976,\"mem_free_kb\":20480,\"mem_avail_kb\":46080,\"mem_used_kb\":80896,",
        "\"mem_kernel_kb\":10240,\"mem_cache_kb\":25600,\"swap_total_kb\":65536,\"swap_free_kb\":61440}"
    ));
}

#[test]
fn sampler_reuses_data_for_one_second_after_io_completes() {
    let mut sampler = SystemSampler::new(fixture());
    let start = Instant::now();
    let end = start + Duration::from_secs(3);
    let clock = Cell::new(start);
    let first = sampler.snapshot_with(|| clock.replace(end)).unwrap();
    sampler.proc_root.push("missing");
    assert_eq!(
        sampler
            .snapshot_with(|| end + Duration::from_millis(999))
            .unwrap(),
        first
    );
    assert!(sampler.snapshot_with(|| end + MIN_INTERVAL).is_err());
    assert!(sampler.snapshot_with(|| start).is_err());
    sampler.proc_root.pop();
    let next = end + MIN_INTERVAL;
    sampler.last_cpu = Some((
        end,
        CpuTicks {
            total: 515,
            idle: 400,
        },
    ));
    assert_eq!(sampler.snapshot_with(|| next).unwrap().cpu_percent, 50.0);
    assert_eq!(sampler.snapshot_with(|| next).unwrap().cpu_percent, 50.0);
}

#[test]
fn cpu_counts_idle_and_iowait_once_and_ignores_guest_columns() {
    let first = CpuTicks::parse("cpu 100 20 30 400 50 5 10 0 60 5").unwrap();
    assert_eq!(
        first,
        CpuTicks {
            total: 615,
            idle: 450
        }
    );
    let next = CpuTicks::parse("cpu\t200 20 30 460 90 5 10 0 160 5").unwrap();
    assert_eq!(next.percent_since(first, MIN_INTERVAL), 50.0);
    let io_only = CpuTicks::parse("cpu 0 0 0 0 100").unwrap();
    assert_eq!(
        io_only.percent_since(CpuTicks::default(), MIN_INTERVAL),
        0.0
    );
    assert_eq!(
        CpuTicks::parse("cpu 1 2 3 4"),
        Some(CpuTicks { total: 10, idle: 4 })
    );
}

#[test]
fn cpu_rejects_invalid_counter_input() {
    for line in [
        "",
        "cpu0 1 2 3 4",
        "cpu 1 2 3",
        "cpu 1 x 3 4",
        "cpu 1 -2 3 4",
        "cpu 9223372036854775807 1 0 0",
    ] {
        assert_eq!(CpuTicks::parse(line), None, "{line}");
    }
}

#[test]
fn cpu_handles_stale_reset_and_idle_skew() {
    let previous = CpuTicks {
        total: 100,
        idle: 60,
    };
    for (total, idle, elapsed, expected) in [
        (200, 120, 1, 40.0),
        (200, 60, 30, 100.0),
        (200, 190, 1, 0.0),
        (100, 60, 1, -1.0),
        (200, 120, 0, -1.0),
        (200, 120, 31, -1.0),
        (90, 80, 1, -1.0),
        (200, 50, 1, -1.0),
    ] {
        assert_eq!(
            CpuTicks { total, idle }.percent_since(previous, Duration::from_secs(elapsed)),
            expected
        );
    }
}

#[test]
fn memory_accepts_older_kernels_and_clamps_negative_buckets() {
    let m = MemoryStats::parse(
        "MemTotal: 50 kB\nMemFree: 30 kB\nCached: 9 kB\nShmem: 100 kB\nHugePages_Total: 0",
    )
    .unwrap();
    assert_eq!(
        (
            m.mem_avail_kb,
            m.swap_total_kb,
            m.mem_cache_kb,
            m.mem_used_kb
        ),
        (0, 0, 0, 20)
    );
    let m = MemoryStats::parse("MemTotal: 50 kB\nMemFree: 40 kB\nBuffers: 20 kB").unwrap();
    assert_eq!((m.mem_cache_kb, m.mem_used_kb), (20, 0));
    for text in [
        "MemFree: 30 kB",
        "MemTotal: -100 kB",
        "MemTotal: 10 kB\nCached: 18446744073709551615 kB\nBuffers: 1 kB",
    ] {
        assert!(MemoryStats::parse(text).is_err());
    }
}

#[test]
fn malformed_proc_files_fail_cleanly() {
    for text in ["", "0.3 0.2", "NaN 0.2 1.0", "0.1 inf 0.3", "0.1 0.2 -1"] {
        assert!(parse_load(text).is_err());
    }
    for text in ["", "-1.3", "12.invalid", "9.9.9"] {
        assert!(parse_uptime(text).is_err());
    }
    assert_eq!(parse_uptime("  4  12.0").unwrap(), 4);
    assert_eq!(
        parse_uptime("9007199254740993.95 0.00").unwrap(),
        9_007_199_254_740_993
    );
}
