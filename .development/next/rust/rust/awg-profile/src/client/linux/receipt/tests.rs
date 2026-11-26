use super::*;
use crate::client::{specification, uapi_message};
use nfqws2_store::Store;
use std::{
    os::unix::{fs::symlink, net::UnixListener},
    process::{Command, Stdio},
    thread,
    time::Instant,
};

const WORKER: &str = "client::linux::receipt::tests::fixture_uapi_engine";
const FIXTURE: &str = "N2S_TEST_OWNED_AWG_SOCKET";

#[test]
fn native_vacancy_requires_exact_terminal_start_and_absent_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let pid = 321;
    let proc_dir = root.join("proc/321");
    let boot = "01010101-0101-0101-0101-010101010101";
    for path in [
        "proc/sys/kernel/random",
        "proc/321",
        "var/run/amneziawg",
        "sys/class/net",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    fs::write(root.join("proc/sys/kernel/random/boot_id"), boot).unwrap();
    let socket = super::super::socket_path(root, "awg0");
    let original = UnixListener::bind(&socket).unwrap();
    let record = Receipt {
        version: 1,
        boot: boot.into(),
        id: "test".into(),
        iface: "awg0".into(),
        config: [1; 32],
        keys: [1; 32],
        pid,
        started: 500,
        executable: (1, 1),
        ifindex: 9,
        socket: identity(&socket).unwrap(),
        nested: None,
    };
    let stat = |state, started| {
        fs::write(
            proc_dir.join("stat"),
            format!("{pid} (awg worker) {state} {} {started}", "0 ".repeat(18)),
        )
        .unwrap();
    };
    stat("Z", 500);
    assert!(start_time(&proc_dir).is_err());
    assert!(record.vacant(root, &socket).is_err());
    fs::remove_file(&socket).unwrap();
    let foreign = UnixListener::bind(&socket).unwrap();
    assert!(!record.vacant(root, &socket).unwrap());
    drop((original, foreign));
    fs::remove_file(&socket).unwrap();
    let link = root.join("sys/class/net/awg0");
    fs::create_dir(&link).unwrap();
    assert!(!record.vacant(root, &socket).unwrap());
    fs::remove_dir(link).unwrap();
    assert!(record.vacant(root, &socket).unwrap());
    stat("Z", 501);
    assert!(record.vacant(root, &socket).is_err());
    stat("S", 500);
    assert_eq!(start_time(&proc_dir).unwrap(), 500);
    assert!(!record.vacant(root, &socket).unwrap());
    stat("S", 501);
    assert!(record.vacant(root, &socket).unwrap());
}

#[test]
fn unselected_socket_requires_current_native_receipts_and_exact_own_uapi_mark() {
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let iface = "awg0";
    let pid = std::process::id();
    let proc_dir = root.join("proc").join(pid.to_string());
    for path in [
        "proc/sys/kernel/random",
        "var/run/amneziawg",
        "sys/class/net/awg0",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    fs::create_dir(&proc_dir).unwrap();
    let executable = std::env::current_exe().unwrap();
    symlink(&executable, proc_dir.join("exe")).unwrap();
    fs::write(proc_dir.join("cmdline"), b"amneziawg-go\0-f\0awg0\0").unwrap();
    let stat = |current: u32| {
        fs::write(
            proc_dir.join("stat"),
            format!("{pid} (awg) S {} {current}", "0 ".repeat(18)),
        )
        .unwrap();
    };
    stat(500);
    fs::write(
        root.join("proc/sys/kernel/random/boot_id"),
        "01010101-0101-0101-0101-010101010101",
    )
    .unwrap();
    fs::write(root.join("sys/class/net/awg0/ifindex"), "9").unwrap();

    let db = Store::open(root.join("data")).unwrap();
    crate::import(&db, &crate::tests::input(), "fixture").unwrap();
    crate::edit_document(&db, |doc| {
        let cfg = &mut doc["servers"].as_array_mut().unwrap().last_mut().unwrap()["config"];
        cfg["enabled"] = true.into();
        cfg["client"]["enabled"] = true.into();
        cfg["client"]["rust_managed"] = true.into();
        cfg["client_iface"] = iface.into();
        Ok(())
    })
    .unwrap();
    let doc = crate::read(&db).unwrap();
    let row = doc["servers"].as_array().unwrap().last().unwrap();
    let spec = specification(&doc, row).unwrap();
    let endpoint = "192.0.2.1:5".parse().unwrap();
    let outer = crate::client::NestedOuter {
        iface: "awg2".into(),
        peer_hex: "1".repeat(64),
    };
    let routes = serde_json::json!({
        "iface":"awg0", "outer":"awg2", "endpoint":"192.0.2.1", "source":"192.0.2.2"
    });
    let nested = serde_json::from_value(serde_json::json!({
        "outer":outer, "routes":routes, "mtu":1360, "outer_mtu":1420
    }))
    .unwrap();
    let socket = super::super::socket_path(root, iface);
    let sidecar = socket.with_extension("n2s-nested.json");
    let mut file = tempfile::NamedTempFile::new_in(socket.parent().unwrap()).unwrap();
    serde_json::to_writer(&mut file, &routes).unwrap();
    file.persist(&sidecar).unwrap();

    let listener = UnixListener::bind(&socket).unwrap();
    let message = uapi_message(&crate::tests::input(), endpoint).unwrap();
    let keys = message
        .lines()
        .filter(|line| line.starts_with("private_key=") || line.starts_with("public_key="))
        .collect::<Vec<_>>()
        .join("\n");
    let mark = Arc::new(AtomicU32::new(0xa000_0000));
    let actual = mark.clone();
    let worker = thread::spawn(move || {
        for mut stream in listener.incoming().take(4).map(Result::unwrap) {
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert_eq!(request, "get=1\n\n");
            write!(
                stream,
                "{keys}\nfwmark={}\nendpoint={endpoint}\nerrno=0\n\n",
                actual.load(Ordering::Relaxed)
            )
            .unwrap();
        }
    });
    let runtime = Runtime::new(root, executable);
    let record = Receipt::capture(&runtime, &spec, pid, &socket, Some(nested)).unwrap();
    record.persist(&socket).unwrap();
    let owned = || {
        super::super::owns_nested_socket(
            root,
            &spec,
            &outer,
            endpoint,
            Instant::now() + Duration::from_secs(1),
        )
    };
    assert!(owned().unwrap());
    stat(501);
    assert!(owned().is_err());
    stat(500);
    mark.store(0xa000_0001, Ordering::Relaxed);
    assert!(!owned().unwrap());
    fs::remove_file(sidecar).unwrap();
    assert!(!owned().unwrap());
    worker.join().unwrap();
}

#[test]
fn fixture_uapi_engine() {
    let Some(socket) = std::env::var_os(FIXTURE) else {
        return;
    };
    // Bound every run, including diagnostic failures in the parent.
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(20));
        std::process::exit(1)
    });
    let listener = UnixListener::bind(socket).unwrap();
    let msg = uapi_message(&crate::tests::input(), "192.0.2.1:5".parse().unwrap()).unwrap();
    let pair = msg
        .lines()
        .filter(|l| l.starts_with("private_key=") || l.starts_with("public_key="))
        .collect::<Vec<_>>()
        .join("\n");
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut req = String::new();
        stream.read_to_string(&mut req).unwrap();
        assert_eq!(req, "get=1\n\n");
        write!(
            stream,
            "{pair}\nendpoint=192.0.2.1:5\nlast_handshake_time_sec=12345\nerrno=0\n\n"
        )
        .unwrap();
    }
}

#[test]
fn panel_restart_reclaims_only_the_exact_own_engine_and_explicit_stop_releases_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for path in [
        "proc/sys/kernel/random",
        "var/run/amneziawg",
        "sys/class/net/awg0",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    fs::write(
        root.join("proc/sys/kernel/random/boot_id"),
        "01010101-0101-0101-0101-010101010101",
    )
    .unwrap();
    fs::write(root.join("sys/class/net/awg0/ifindex"), "9").unwrap();
    let db = Store::open(root.join("data")).unwrap();
    crate::import(&db, &crate::tests::input(), "test").unwrap();
    crate::edit_document(&db, |d| {
        let cfg = &mut d["servers"].as_array_mut().unwrap().last_mut().unwrap()["config"];
        cfg["enabled"] = true.into();
        cfg["client"]["enabled"] = true.into();
        cfg["client"]["rust_managed"] = true.into();
        cfg["client_iface"] = "awg0".into();
        Ok(())
    })
    .unwrap();
    let doc = crate::read(&db).unwrap();
    let row = doc["servers"].as_array().unwrap().last().unwrap();
    let spec = specification(&doc, row).unwrap();
    let suite = std::path::absolute(std::env::args_os().next().unwrap()).unwrap();
    let socket = super::super::socket_path(root, "awg0");
    let mut child = Command::new(&suite)
        .args(["--exact", WORKER, "--test-threads=1"])
        .env(FIXTURE, &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let proc_dir = root.join("proc").join(pid.to_string());
    fs::create_dir(&proc_dir).unwrap();
    symlink(&suite, proc_dir.join("exe")).unwrap();
    fs::write(proc_dir.join("cmdline"), b"amneziawg-go\0-f\0awg0\0").unwrap();
    let stat = |start: u32| format!("{pid} (awg) S {} {start}", "0 ".repeat(18));
    fs::write(proc_dir.join("stat"), stat(150)).unwrap();
    let until = Instant::now() + Duration::from_secs(4);
    while !socket.exists() {
        assert!(Instant::now() < until && child.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(10));
    }
    let dev = root.join("sys/class/net/awg0");
    let gone = proc_dir.clone();
    let reaper = thread::spawn(move || {
        let result = child.wait().unwrap();
        fs::remove_dir_all(dev).unwrap();
        fs::remove_dir_all(gone).unwrap();
        result
    });
    let panel = Runtime::new(root, suite.clone());
    let proof = Receipt::capture(&panel, &spec, pid, &socket, None).unwrap();
    proof.persist(&socket).unwrap();
    panel.restore_clients(&db, &[]).unwrap();
    assert!(panel.has_managed_clients());
    panel.shutdown_clients().unwrap();
    drop(panel);
    assert!(socket.exists() && !reaper.is_finished());
    let next = Runtime::new(root, suite);
    fs::write(proc_dir.join("stat"), stat(151)).unwrap();
    assert!(super::super::resume(&next, &spec).is_err());
    assert!(!reaper.is_finished() && read(&socket).unwrap() == Some(proof.clone()));
    fs::write(proc_dir.join("stat"), stat(150)).unwrap();
    let mut edited = specification(&doc, row).unwrap();
    edited.conf.push('\n');
    assert!(super::super::resume(&next, &edited).is_err());
    assert!(super::super::resume_after_edit(&next, &edited, Some([1; 32])).is_err());
    let key = edited.conf.find("PublicKey = ").unwrap() + "PublicKey = ".len();
    let unlike = if edited.conf.as_bytes()[key] == b'A' {
        "B"
    } else {
        "A"
    };
    edited.conf.replace_range(key..=key, unlike);
    assert!(super::super::resume_after_edit(&next, &edited, Some(proof.config)).is_err());
    assert!(!reaper.is_finished() && read(&socket).unwrap() == Some(proof.clone()));
    crate::edit_document(&db, |d| {
        let row = d["servers"].as_array_mut().unwrap().last_mut().unwrap();
        row["config"]["endpoint"] = "192.0.2.10:444".into();
        row[crate::client::settings::PENDING_PROFILE] = serde_json::json!(proof.config);
        Ok(())
    })
    .unwrap();
    assert!(next
        .restore_clients_with_transport(&db, &[], |request| {
            assert_eq!(request.endpoint.to_string(), "192.0.2.10:444");
            assert!(socket.exists() && !reaper.is_finished());
            Err(io::ErrorKind::WouldBlock.into())
        })
        .is_err());
    assert!(next.has_managed_clients() && read(&socket).unwrap().unwrap().pid == pid);
    next.server_enabled(&db, &spec.id, false, &[]).unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(reaper.join().unwrap().signal(), Some(libc::SIGTERM));
    assert!(!socket.exists() && read(&socket).unwrap().is_none());
    assert_eq!(
        crate::client::find(&crate::read(&db).unwrap(), &spec.id).unwrap()["config"]["client"]
            ["enabled"],
        false
    );
}
