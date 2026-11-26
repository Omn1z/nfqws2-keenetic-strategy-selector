use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const FILES: &[&str] = &[
    "conn/conn.go",
    "conn/bind_std.go",
    "conn/bind_std_test.go",
    "device/queueconstants_default.go",
    "device/device_test.go",
];

fn fixture(root: &Path) -> PathBuf {
    let source = root.join("pinned source");
    let original = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/upstream");
    for name in FILES {
        let path = source.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::copy(original.join(name), path).unwrap();
    }
    source
}

fn run(source: &Path, output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nfqws2-engine-overlay"))
        .arg("-source")
        .arg(source)
        .arg("-output")
        .arg(output)
        .output()
        .unwrap()
}

#[test]
fn normal_cli_builds_all_four_files_and_preserves_upstream() {
    let temp = TempDir::new().unwrap();
    let source = fixture(temp.path());
    let output = temp.path().join("overlay & files");
    // Patched sources normalize CRLF; test files preserve their original bytes.
    for name in FILES {
        let file = source.join(name);
        let text = fs::read_to_string(&file)
            .unwrap()
            .replace("\r\n", "\n")
            .replace('\n', "\r\n");
        fs::write(file, text).unwrap();
    }
    let originals: BTreeMap<_, _> = FILES
        .iter()
        .map(|&n| (n, fs::read(source.join(n)).unwrap()))
        .collect();
    let result = run(&source, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        output.join("overlay.json").to_str().unwrap()
    );
    let manifest_bytes = fs::read(output.join("overlay.json")).unwrap();
    let manifest: BTreeMap<String, BTreeMap<PathBuf, PathBuf>> =
        serde_json::from_slice(&manifest_bytes).unwrap();
    let paths = &manifest["Replace"];
    assert_eq!(paths.len(), 4);
    let conn = fs::read_to_string(&paths[&source.join("conn/conn.go")]).unwrap();
    assert!(conn.contains("IdealBatchSize = 64") && !conn.contains('\r'));
    let queues =
        fs::read_to_string(&paths[&source.join("device/queueconstants_default.go")]).unwrap();
    for line in [
        "QueueStagedSize            = 8",
        "QueueOutboundSize          = 32",
        "QueueInboundSize           = 32",
        "QueueHandshakeSize         = 128",
        "MaxSegmentSize             = (1 << 16) - 1",
        "PreallocatedBuffersPerPool = 0",
    ] {
        assert!(queues.contains(line), "{line}");
    }
    assert!(!queues.contains("import") && !queues.contains('\r'));
    for (name, addition) in [
        (
            "conn/bind_std_test.go",
            include_bytes!("../testdata/conn_memory_tests.go.txt").as_slice(),
        ),
        (
            "device/device_test.go",
            include_bytes!("../testdata/device_memory_tests.go.txt").as_slice(),
        ),
    ] {
        let expected = [originals[name].as_slice(), addition].concat();
        assert_eq!(fs::read(&paths[&source.join(name)]).unwrap(), expected);
    }
    assert!(run(&source, &output).status.success());
    assert_eq!(
        fs::read(output.join("overlay.json")).unwrap(),
        manifest_bytes
    );
    for (name, data) in originals {
        assert_eq!(fs::read(source.join(name)).unwrap(), data);
    }
}

#[test]
fn changed_or_ambiguous_constants_leave_previous_overlay_intact() {
    for (name, old, new) in [
        (
            "conn/bind_std.go",
            "udpSegmentMaxDatagrams = 64",
            "udpSegmentMaxDatagrams = 128",
        ),
        (
            "conn/bind_std.go",
            "udpSegmentMaxDatagrams = 64",
            "udpSegmentMaxDatagrams = 640",
        ),
        (
            "conn/conn.go",
            "IdealBatchSize = 128",
            "IdealBatchSize = 128 + 1",
        ),
        (
            "conn/conn.go",
            "IdealBatchSize = 128",
            "IdealBatchSize = 256",
        ),
        (
            "conn/conn.go",
            "IdealBatchSize = 128",
            "IdealBatchSize = 128 // IdealBatchSize = 128",
        ),
        (
            "device/queueconstants_default.go",
            "QueueInboundSize           = 1024",
            "QueueInboundSize           = 2048",
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let source = fixture(temp.path());
        let output = temp.path().join("out");
        assert!(run(&source, &output).status.success());
        let manifest = fs::read(output.join("overlay.json")).unwrap();
        let existing = output.join("conn/conn.go");
        fs::write(&existing, b"previous generation").unwrap();
        let file = source.join(name);
        fs::write(&file, fs::read_to_string(&file).unwrap().replace(old, new)).unwrap();
        assert_eq!(run(&source, &output).status.code(), Some(1));
        assert_eq!(fs::read(existing).unwrap(), b"previous generation");
        assert_eq!(fs::read(output.join("overlay.json")).unwrap(), manifest);
    }
}

#[test]
fn output_inside_source_and_missing_required_options_are_rejected() {
    let temp = TempDir::new().unwrap();
    let source = fixture(temp.path());
    for output in [&source, &source.join("generated")] {
        assert_eq!(run(&source, output).status.code(), Some(1));
    }
    assert!(!source.join("generated").exists());
    let exe = env!("CARGO_BIN_EXE_nfqws2-engine-overlay");
    assert_eq!(
        Command::new(exe)
            .arg("-source")
            .arg(source)
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert!(Command::new(exe)
        .arg("--help")
        .output()
        .unwrap()
        .status
        .success());
}

#[cfg(unix)]
#[test]
fn symlink_back_into_source_is_rejected() {
    let temp = TempDir::new().unwrap();
    let source = fixture(temp.path());
    let output = temp.path().join("out");
    fs::create_dir(&output).unwrap();
    std::os::unix::fs::symlink(source.join("device"), output.join("device")).unwrap();
    assert_eq!(run(&source, &output).status.code(), Some(1));
    assert!(!output.join("overlay.json").exists());
}
