use super::*;
use tempfile::tempdir;

fn process(root: &Path, pid: u32, ticks: u64, start: u64, pages: u64) {
    let path = root.join(pid.to_string());
    fs::create_dir_all(&path).unwrap();
    let mut fields = vec!["0".to_string(); 22];
    fields[0] = "S".into();
    fields[11] = ticks.to_string();
    fields[19] = start.to_string();
    fs::write(
        path.join("stat"),
        format!("{pid} (has ) spaces) {}", fields.join(" ")),
    )
    .unwrap();
    fs::write(path.join("statm"), format!("100000 {pages} 0")).unwrap();
}

#[test]
fn dashboard_samples_all_rss_but_retains_only_ten_services_and_eight_sensors() {
    let root = tempdir().unwrap();
    let thermal = tempdir().unwrap();
    for j in 1..=12 {
        process(root.path(), j, 10, 1000, j as u64 * 512);
        let dir = thermal.path().join(format!("thermal_zone{j}"));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("temp"), format!("{}", (40 + j) * 1000)).unwrap();
    }
    process(root.path(), 99, 0, 0, 5);
    let hottest = thermal.path().join("thermal_zone12");
    fs::write(hottest.join("type"), " chip \n").unwrap();
    fs::write(hottest.join("temp"), "80").unwrap();
    fs::write(root.path().join("uptime"), "100.25 0").unwrap();
    let mut mon = Monitor::new(root.path(), thermal.path());
    mon.page_kb = 4;
    let now = Instant::now();
    let mut first = mon.snapshot_with(|| now);
    assert_eq!(first.system.uptime_sec, 100);
    assert_eq!(first.system.cpu_percent, -1.0);
    assert_eq!(first.mem_apps_kb, (78 * 512 + 5) * 4);
    let rows = first.services.as_mut().unwrap();
    assert_eq!(rows.len(), 10);
    assert_eq!((rows[0].pid, rows[9].pid), (12, 3));
    assert_eq!(rows[0].name, "has ) spaces");
    assert_eq!(rows[0].uptime_sec, 90);
    assert_eq!(rows[0].cpu_percent, -1.0);
    let zones = first.temps.as_ref().unwrap();
    assert_eq!(zones.len(), 8);
    assert_eq!(
        zones[0],
        TempZone {
            label: "chip".into(),
            c: 80
        }
    );
    rows[0].name.clear();
    process(root.path(), 12, 310, 1000, 12 * 512);
    let cached = mon.snapshot_with(|| now + Duration::from_millis(999));
    assert_eq!(cached.services.unwrap()[0].name, "has ) spaces");
    let second = mon.snapshot_with(|| now + Duration::from_secs(2));
    assert_eq!(second.services.unwrap()[0].cpu_percent, 150.0);
    process(root.path(), 12, 600, 5000, 12 * 512);
    fs::remove_dir_all(root.path().join("11")).unwrap();
    let third = mon.snapshot_with(|| now + Duration::from_secs(4));
    assert_eq!(third.services.unwrap()[0].cpu_percent, -1.0);
    assert!(!mon.last.contains_key(&11));
}

#[test]
fn missing_and_empty_proc_have_distinct_json_arrays() {
    let root = tempdir().unwrap();
    let missing = root.path().join("missing");
    let stats = Monitor::new(&missing, &missing).snapshot();
    let json = serde_json::to_value(stats).unwrap();
    assert_eq!(json["cpu_percent"], -1.0);
    assert_eq!(json["mem_apps_kb"], 0);
    assert!(json["temps"].is_null() && json["services"].is_null());
    assert_eq!(json.as_object().unwrap().len(), 14);
    assert_eq!(
        Monitor::new(root.path(), &missing).snapshot().services,
        Some(vec![])
    );
}

#[test]
fn process_cpu_rejects_old_samples_counter_reset_and_pid_reuse() {
    let ts = Instant::now();
    let prev = ProcessCpu {
        at: ts,
        ticks: 100,
        start: 10,
        live: true,
    };
    for (ticks, start, secs, want) in [
        (400, 10, 2, 150.0),
        (99, 10, 1, -1.0),
        (101, 50, 1, -1.0),
        (101, 10, 0, -1.0),
        (101, 10, 31, -1.0),
    ] {
        assert_eq!(
            process_percent(&prev, ticks, start, ts + Duration::from_secs(secs)),
            want
        );
    }
    assert!(parse_stat("1 (broken)").is_none());
}
