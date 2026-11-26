//! Executable fixture used only by scripts/test-rust-runs.py.
use std::{env, fs, thread, time::Duration};
fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    assert_eq!(args[0], "--disable");
    assert!(args.iter().any(|v| v == "--head"));
    assert!(args.windows(2).any(|v| v == ["--proto", "=https"]));
    assert!(args.windows(2).any(|v| v == ["--noproxy", "*"]));
    assert!(!args.iter().any(|v| v == "--insecure" || v == "--location"));
    let host = args
        .last()
        .unwrap()
        .strip_prefix("https://")
        .unwrap()
        .strip_suffix('/')
        .unwrap();
    assert!(
        host.ends_with(".test") && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
    );
    let root = std::path::PathBuf::from(env::var_os("N2S_RUN_FIXTURE").unwrap());
    fs::write(root.join(host), b"head").unwrap();
    if host.starts_with("slow") {
        thread::sleep(Duration::from_secs(3));
    }
    print!("{} 0.042", if host == "reject.test" { 404 } else { 204 });
}
