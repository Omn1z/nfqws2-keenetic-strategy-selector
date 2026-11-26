use std::{path::Path, process::Command};

#[test]
fn reads_proc_fixture_and_reports_missing_sources() {
    let bin = env!("CARGO_BIN_EXE_nfqws2-sysinfo");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/proc");
    let ok = Command::new(bin).arg(&fixture).output().unwrap();
    assert!(ok.status.success());
    let json = String::from_utf8(ok.stdout).unwrap();
    assert!(json.contains("\"cpu_percent\":-1"));
    assert!(json.contains("\"mem_total_kb\":"));
    let missing = Command::new(bin)
        .arg(fixture.join("missing"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    let usage = Command::new(bin).args(["one", "two"]).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
}
