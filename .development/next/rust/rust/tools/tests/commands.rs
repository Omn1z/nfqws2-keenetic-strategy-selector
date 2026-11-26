use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

#[test]
fn module_names_preserve_arguments_stdio_and_exit_codes() {
    let temp = tempfile::tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_nfqws2-tools"));
    let alias = |name: &str| {
        let path = temp
            .path()
            .join(format!("nfqws2-{name}{}", std::env::consts::EXE_SUFFIX));
        #[cfg(unix)]
        std::os::unix::fs::symlink(binary, &path).unwrap();
        #[cfg(not(unix))]
        fs::copy(binary, &path).unwrap();
        Command::new(path)
    };
    let input = temp.path().join("list.txt");
    fs::write(&input, "office.example\n").unwrap();
    let mut geo = alias("geo");
    geo.args(["extract-checked", "text"]).arg(input);
    let found = geo.arg("all").output().unwrap();
    assert!(found.status.success());
    assert_eq!(
        serde_json::from_slice::<Vec<String>>(&found.stdout).unwrap(),
        ["office.example"]
    );
    let absent = Command::new(geo.get_program())
        .args(["extract-checked", "text"])
        .arg(temp.path().join("list.txt"))
        .arg("missing")
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(3));
    let history = alias("runs")
        .arg("history")
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(history.status.success());
    assert!(serde_json::from_slice::<Vec<Value>>(&history.stdout)
        .unwrap()
        .is_empty());
    let version = alias("blockcheck").arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(version.stdout.starts_with(b"nfqws2-blockcheck "));
    let mut compiler = alias("strategies")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"services":[],"source":"","lists_dir":"/opt/etc/nfqws2/lists"}"#)
        .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap()["profiles"],
        0
    );
    assert_eq!(
        Command::new(binary).output().unwrap().status.code(),
        Some(2)
    );
}
