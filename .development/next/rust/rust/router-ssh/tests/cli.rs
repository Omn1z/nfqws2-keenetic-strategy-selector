use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
use tempfile::tempdir;

const EXE: &str = env!("CARGO_BIN_EXE_router-ssh");

fn clean() -> Command {
    let mut cmd = Command::new(EXE);
    for key in [
        "ROUTER_HOST",
        "ROUTER_USER",
        "ROUTER_PORT",
        "ROUTER_PASS",
        "N2S_SSH_PASSWORD_PROMPT",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

#[test]
fn explicit_credentials_and_help() {
    let cases = [
        (vec!["exec", "true"], "router host is required"),
        (
            vec!["--host", "router.local", "exec", "true"],
            "router password is required",
        ),
        (
            vec![
                "--host",
                "  ",
                "--password",
                "fixture-password",
                "exec",
                "true",
            ],
            "router host is required",
        ),
    ];
    for (args, expected) in cases {
        let out = clean().args(args).output().unwrap();
        assert!(!out.status.success());
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains(expected) && !err.contains("fixture-password"));
    }
    let help = clean()
        .env("ROUTER_PASS", "fixture-password")
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(
        text.contains("<host>")
            && text.contains("<password>")
            && !text.contains("fixture-password")
    );
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let path = env::join_paths(
        std::iter::once(dir.to_owned()).chain(env::split_paths(&env::var_os("PATH").unwrap())),
    )
    .unwrap();
    clean()
        .env("PATH", path)
        .env("N2S_FIXTURE_DATA", dir.join("remote"))
        .env("ROUTER_HOST", "127.0.0.1")
        .env("ROUTER_PORT", "2345")
        .env("ROUTER_USER", "fixture-user")
        .env("ROUTER_PASS", " fixture-password ")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn all_commands_use_the_transport_and_preserve_file_contents() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let fake = dir.join(format!("ssh{}", env::consts::EXE_SUFFIX));
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh.rs");
    assert!(Command::new("rustc")
        .arg("--edition=2021")
        .arg(src)
        .arg("-o")
        .arg(fake)
        .status()
        .unwrap()
        .success());
    let ok = run(
        dir,
        &[
            "--password=override-password",
            "--host=127.0.0.2",
            "exec",
            "--timeout",
            "1m0.25s",
            "exec ok",
        ],
    );
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(String::from_utf8(ok.stdout).unwrap().trim(), "exec output");
    let failed = run(dir, &["exec", "exec fail"]);
    assert!(!failed.status.success() && String::from_utf8(failed.stderr).unwrap().contains("23"));
    let start = Instant::now();
    let timeout = run(dir, &["exec", "--timeout=300ms", "sleep"]);
    assert!(
        !timeout.status.success()
            && String::from_utf8(timeout.stderr)
                .unwrap()
                .contains("timed out")
    );
    assert!(start.elapsed() < Duration::from_secs(7));

    let local = dir.join("local.bin");
    let output = dir.join("nested/result.bin");
    let bytes: Vec<_> = (0..=255).cycle().take(70_000).collect();
    fs::write(&local, &bytes).unwrap();
    assert!(run(
        dir,
        &[
            "upload",
            "--mode",
            "0755",
            local.to_str().unwrap(),
            "-d/foo'bar"
        ]
    )
    .status
    .success());
    assert!(
        run(dir, &["download", "--", "-file", output.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert!(!run(dir, &["download", "bad", output.to_str().unwrap()])
        .status
        .success());
    assert_eq!(fs::read(&output).unwrap(), bytes);

    let diag = run(dir, &["diagnose", "--only", "routing,system"]);
    assert!(!diag.status.success());
    let text = String::from_utf8(diag.stdout).unwrap();
    assert!(
        text.contains("===== system =====")
            && text.contains("===== routing =====")
            && text.contains("route fixture")
    );
    assert!(!text.contains("===== conntrack ====="));
    assert!(String::from_utf8(diag.stderr)
        .unwrap()
        .contains("system exited with status 11"));
}
