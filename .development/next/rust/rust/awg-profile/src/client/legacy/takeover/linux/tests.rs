use super::*;
use std::{
    io::BufRead,
    os::unix::{fs::symlink, net::UnixListener},
};

#[test]
fn only_the_confirmed_boot_process_socket_interface_and_profile_can_be_adopted() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for path in [
        "proc/12/fd",
        "proc/net",
        "proc/sys/kernel/random",
        "sys/class/net/awg0",
        "var/run/amneziawg",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    let engine = root.join("engine");
    fs::write(&engine, b"stub").unwrap();
    symlink(&engine, root.join("proc/12/exe")).unwrap();
    symlink("socket:[345]", root.join("proc/12/fd/4")).unwrap();
    fs::write(
        root.join("proc/12/cmdline"),
        b"/opt/usr/bin/amneziawg-go\0awg0\0",
    )
    .unwrap();
    fs::write(
        root.join("proc/12/stat"),
        format!("12 (awg ) test) S {} 123\n", "0 ".repeat(18)),
    )
    .unwrap();
    fs::write(
        root.join("proc/sys/kernel/random/boot_id"),
        "synthetic-boot",
    )
    .unwrap();
    fs::write(root.join("sys/class/net/awg0/ifindex"), "7\n").unwrap();
    fs::write(root.join("sys/class/net/awg0/mtu"), "1420\n").unwrap();
    let line = "1: 22 0 00010000 0001 01 345 /var/run/amneziawg/awg0.sock\n";
    fs::write(root.join("proc/net/unix"), line).unwrap();
    assert!(listener_inode(&line.repeat(2), &socket_name("awg0")).is_err());
    let rt = Runtime::new(root, engine);
    let mut cfg = conf::parse(&crate::tests::input(), 0).unwrap();
    cfg["enabled"] = true.into();
    cfg["client"]["enabled"] = true.into();
    cfg["client_iface"] = "awg0".into();
    let row = json!({"id":"a", "config":cfg});
    let doc = json!({"servers":[row]});
    let spec = specification(&doc, &row).unwrap();
    let msg = uapi_message(&spec.conf, "192.0.2.10:1234".parse().unwrap()).unwrap();
    let private = msg.lines().find(|s| s.starts_with("private_key=")).unwrap();
    let public = msg.lines().find(|s| s.starts_with("public_key=")).unwrap();
    let response = format!("{private}\n{public}\nendpoint=192.0.2.10:1234\nerrno=0\n\n");
    let proof = reported_identity(response.as_bytes()).unwrap();
    let listener = UnixListener::bind(root.join(socket_name("awg0"))).unwrap();
    let db = Store::open(root.join("data")).unwrap();
    let server = std::thread::spawn(move || {
        let mut actions = Vec::new();
        for _ in 0..6 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut read = std::io::BufReader::new(socket.try_clone().unwrap());
            loop {
                let mut request = String::new();
                while !request.ends_with("\n\n") {
                    if read.read_line(&mut request).unwrap() == 0 {
                        break;
                    }
                }
                if request.is_empty() {
                    break;
                }
                if request == "get=1\n\n" {
                    actions.push("get");
                    socket.write_all(response.as_bytes()).unwrap();
                    if actions.len() == 1 {
                        break;
                    } // capture half-closes its write side
                } else {
                    assert!(request.contains("update_only=true"));
                    actions.push("probe");
                    socket.write_all(b"errno=0\n\n").unwrap();
                }
            }
        }
        actions
    });
    let receipt = capture(&rt, &spec).unwrap();
    let seal = receipt.seal().unwrap();
    let serialized = serde_json::to_string(&receipt).unwrap();
    assert!(!serialized.contains("\"nested\""));
    let old: Receipt = serde_json::from_str(&serialized).unwrap();
    assert_eq!(old.seal().unwrap(), seal);
    db.transaction(|tx| tx.save_runtime(PENDING, &BTreeMap::from([("a", receipt)])))
        .unwrap();
    assert!(confirmed(&rt, &db, &spec, proof).is_none());
    Runtime::confirm_go_clients(&db).unwrap();
    let mut tunnel = confirmed(&rt, &db, &spec, proof).unwrap();
    assert!(tunnel.alive() && tunnel.inherited());
    assert!(tunnel.snapshot().unwrap()["running"] == true);
    tunnel.probe().unwrap();
    assert!(super::super::replay(&rt, &db, &spec, [12; 32]).is_err());
    let replayed = super::super::replay(&rt, &db, &spec, seal)
        .unwrap()
        .unwrap();
    let endpoint = "192.0.2.10:1234".parse().unwrap();
    let lease = replayed
        .verified_legacy_predecessor(&spec, endpoint, 1420, false)
        .unwrap();
    assert_eq!(lease.receipt_sha256, seal);
    assert_eq!(lease.endpoint, endpoint);
    assert_eq!(
        server.join().unwrap(),
        ["get", "get", "get", "get", "probe", "get", "get"]
    );

    fs::write(
        root.join("proc/12/stat"),
        format!("12 (same PID, different birth) S {} 124\n", "0 ".repeat(18)),
    )
    .unwrap();
    assert!(super::super::replay(&rt, &db, &spec, seal).is_err());
    fs::write(
        root.join("proc/12/stat"),
        format!("12 (awg ) test) S {} 123\n", "0 ".repeat(18)),
    )
    .unwrap();
    fs::write(root.join("sys/class/net/awg0/ifindex"), "8").unwrap();
    assert!(!tunnel.alive());
    fs::write(root.join("sys/class/net/awg0/ifindex"), "7").unwrap();
    assert!(tunnel.alive());
    fs::remove_file(root.join("proc/12/fd/4")).unwrap();
    symlink("socket:[999]", root.join("proc/12/fd/4")).unwrap();
    assert!(!tunnel.alive());
    fs::write(root.join("proc/sys/kernel/random/boot_id"), "different").unwrap();
    assert!(confirmed(&rt, &db, &spec, proof).is_none());
    assert!(super::super::replay(&rt, &db, &spec, seal).is_err());
    fs::remove_file(root.join(socket_name("awg0"))).unwrap();
    fs::remove_file(root.join("sys/class/net/awg0/ifindex")).unwrap();
    fs::remove_file(root.join("sys/class/net/awg0/mtu")).unwrap();
    fs::remove_dir(root.join("sys/class/net/awg0")).unwrap();
    assert!(super::super::replay(&rt, &db, &spec, seal)
        .unwrap()
        .is_none());
}
