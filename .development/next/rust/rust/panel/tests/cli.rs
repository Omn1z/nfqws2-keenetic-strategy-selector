use std::{path::Path, process::Command};

fn panel(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nfqws2-strategy"));
    cmd.current_dir(dir)
        .env("N2S_DATA", dir.join("unused-data"))
        .env("N2S_MODULE_DIR", dir.join("modules"))
        .env("N2S_NFQWS2_CONF", dir.join("nfqws2.conf"));
    cmd
}
#[test]
fn usage_errors_preserve_data_and_return_exit_two() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["selftest"][..],
        &["selftest", "-s", "-1", "example.test"],
        &["update", "unexpected"],
        &["checkupdate", "unexpected"],
    ] {
        let result = panel(tmp.path()).args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
    assert!(!tmp.path().join("unused-data").exists());
}
#[cfg(feature = "compact")]
#[test]
fn compact_update_reports_package_manager_and_missing_measurement_reports_helper() {
    let tmp = tempfile::tempdir().unwrap();
    let platform = match nfqws2_config::Resolver::current().platform() {
        nfqws2_config::Platform::Entware => "Entware (opkg)",
        nfqws2_config::Platform::OpenWrt => "OpenWrt (apk или opkg)",
    };
    for (args, marker) in [
        (&["checkupdate"][..], platform),
        (&["update"][..], platform),
        (&["selftest", "example.test"][..], "nfqws2-strategy-runs"),
    ] {
        let result = panel(tmp.path()).args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains(marker));
    }
}
#[cfg(all(unix, feature = "embedded-runs", not(feature = "compact")))]
#[test]
fn full_cli_reports_release_and_current_https_from_isolated_transport() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let tool = tmp.path().join("curl");
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "mips" if cfg!(target_endian = "little") => "mipsle",
        "mips" => "mips",
        _ => return,
    };
    fs::write(&tool,format!("#!/bin/sh\nfor address in \"$@\"; do :; done\ncase \"$address\" in\n  https://api.github.com/repos/*/releases/latest) echo '{{\"tag_name\":\"v9999.0.0\",\"assets\":[{{\"name\":\"SHA256SUMS\"}},{{\"name\":\"nfqws2-strategy-rust-linux-{arch}\"}}]}}' ;;\n  https://local.example/) echo '204 0.013' ;;\n  https://Local.example/) echo '205 0.013' ;;\n  https://Local.example./) echo '206 0.013' ;;\n  https://127.0.0.1/) echo '207 0.013' ;;\n  *) exit 8 ;;\nesac\n")).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    let call = |args: &[&str]| {
        let result = panel(tmp.path())
            .env("PATH", tmp.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()
    };
    assert_eq!(call(&["checkupdate"])["latest"], "v9999.0.0");
    let hosts = [
        "local.example",
        "Local.example",
        "Local.example.",
        "local.example",
        "127.0.0.1",
    ];
    let args: Vec<_> = ["selftest", "--current"].into_iter().chain(hosts).collect();
    let report = call(&args);
    assert_eq!(report["mode"], "current_https");
    assert_eq!(report["results"].as_array().unwrap().len(), hosts.len());
    for (i, (host, code)) in hosts.into_iter().zip([204, 205, 206, 204, 207]).enumerate() {
        assert_eq!(report["results"][i]["host"], host);
        assert_eq!(report["results"][i]["ttfb_ms"], 13);
        assert_eq!(report["results"][i]["code"], code);
    }
    assert!(!tmp.path().join("unused-data").exists());
}
