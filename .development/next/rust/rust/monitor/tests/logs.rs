use nfqws2_monitor::LogBuffer;
use std::{
    fs,
    io::Write,
    sync::{Arc, Mutex},
};
use tempfile::tempdir;

#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Vec<u8>>>);
impl Write for Memory {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn standard_and_proxy_lines_use_separate_outputs() {
    let root = tempdir().unwrap();
    let path = root.path().join("panel.log.proxy");
    let output = Memory::default();
    let log = LogBuffer::new(Box::new(output.clone()), Some(path.clone()));
    assert!(!path.exists());
    let lines = [
        "tgws: connected to pool",
        "tgws: Fake-TLS verify failed -> masking via example.test",
        "tgws: WS session closed (relay: error reading closed socket)",
        "tgws: H2 session closed (HTTP download: MTProto transport error -404)",
        "tgws: bad handshake (wrong secret or proto)",
        "socks5: proxy listening",
        "tgws: listener failed; reopening",
        "socks5: autostart: address in use",
        "proxy: save config failed",
        "engine reload completed",
    ];
    for text in lines {
        for part in text.as_bytes().chunks(5) {
            log.write_bytes(part);
        }
        log.write_bytes(b"\n");
    }
    log.append("socks5", "warn", "restart delayed");
    let common = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert_eq!(common.lines().count(), 1);
    assert!(common.ends_with("[system] engine reload completed\n"));
    let proxy = fs::read_to_string(&path).unwrap();
    assert_eq!(proxy.lines().count(), 6);
    assert!(proxy.contains("MTProto transport error"));
    let stats = log.snapshot("socks5", 0);
    assert_eq!(
        stats
            .entries
            .iter()
            .map(|e| e.level.as_str())
            .collect::<Vec<_>>(),
        ["error", "warn"]
    );
    assert_eq!(
        stats.modules.unwrap(),
        ["proxy", "socks5", "system", "tgws"]
    );
}

#[test]
fn ring_limits_order_filter_clear_and_toggle() {
    let log = LogBuffer::default();
    assert!(log.enabled());
    for i in 0..2100 {
        log.append(if i % 2 == 0 { "a" } else { "b" }, "info", &i.to_string());
    }
    let entries = log.snapshot("all", -1).entries;
    assert_eq!(entries.len(), 2000);
    assert_eq!(entries[0].msg, "100");
    assert_eq!(
        log.snapshot("a", 2)
            .entries
            .iter()
            .map(|e| e.msg.as_str())
            .collect::<Vec<_>>(),
        ["2096", "2098"]
    );
    log.set_enabled(false);
    log.append("hidden", "warn", "not retained");
    log.write_bytes(b"disabled\n");
    assert!(log.snapshot("hidden", 0).entries.is_empty());
    log.clear();
    assert_eq!(
        serde_json::to_value(log.snapshot("", 0)).unwrap(),
        serde_json::json!({"entries":[],"modules":null})
    );
    log.set_enabled(true);
    log.write_bytes(b"GET /api/dashboard\n");
    assert_eq!(log.snapshot("http", 1).entries.len(), 1);
}

#[test]
fn severities_after_long_lines_and_utf8_boundaries_are_retained() {
    let log = LogBuffer::default();
    log.write_bytes(b"run: ");
    for _ in 0..128 {
        log.write_bytes(&[b'x'; 2048]);
    }
    log.write_bytes(b" fa");
    log.write_bytes(b"ILed\n");
    let s = log.snapshot("run", 1);
    assert_eq!(s.entries[0].level, "error");
    assert_eq!(s.entries[0].msg.len(), 2000);
    log.append("system", "warn", &format!("{}😀", "x".repeat(1999)));
    assert!(log.snapshot("system", 1).entries[0]
        .msg
        .ends_with('\u{fffd}'));
}

#[test]
fn oversized_proxy_file_and_new_writes_keep_complete_recent_records() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("warnings.log");
    fs::write(
        &path,
        format!("{}last warning\n", "old record\n".repeat(15000)),
    )
    .unwrap();
    let log = LogBuffer::new(Box::new(std::io::sink()), Some(path.clone()));
    let before = fs::read_to_string(&path).unwrap();
    assert!(
        before.starts_with("old record\n")
            && before.ends_with("last warning\n")
            && before.len() <= 128 * 1024
    );
    for i in 0..400 {
        log.append("proxy", "warn", &format!("{i:03} {}", "x".repeat(1019)));
        assert!(fs::metadata(&path).unwrap().len() <= 128 * 1024);
    }
    let after = fs::read_to_string(&path).unwrap();
    assert!(after
        .lines()
        .all(|l| l.len() == 19 + " [proxy] ".len() + 4 + 1019));
    assert!(after.lines().last().unwrap().contains("[proxy] 399 "));
}
