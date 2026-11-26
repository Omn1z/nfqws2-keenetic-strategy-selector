use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn start_without_roots(config: Value) -> Output {
    let working = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nfqws2-tgws"))
        .env("SSL_CERT_FILE", working.path().join("missing.pem"))
        .env("SSL_CERT_DIR", working.path().join("missing"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let commands = format!(
        "{}\nstop\n",
        json!({"listen":"127.0.0.1:0","config":config})
    );
    stdin.write_all(commands.as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn legacy_tcp_and_plain_ws_start_without_ca_roots_but_native_wss_requires_them() {
    for plain in [false, true] {
        let output = start_without_roots(json!({
            "pool_size":0,
            "disable_secure":plain,
            "cfproxy":plain,
            "cfproxy_user_domains":["relay.example.test"],
            "cfproxy_worker_domains":[],
        }));
        let output_text = std::str::from_utf8(&output.stdout).unwrap();
        assert!(output.status.success(), "{output_text}");
        let frames: Vec<Value> = output_text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(frames.len(), 2, "{output_text}");
        assert_eq!(frames[0]["ready"], true);
        assert_eq!(frames[0]["configured_plain_ws"], true);
        assert_eq!(frames[1]["connections"]["total"], 0);
    }

    let output = start_without_roots(json!({"transport":"direct_wss"}));
    assert!(!output.status.success());
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["ready"], false);
    assert!(reply["error"].as_str().unwrap().contains("TLS"));
}
