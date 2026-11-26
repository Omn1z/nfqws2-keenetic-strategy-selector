use super::super::read;
use super::*;
use tempfile::TempDir;

fn fixture() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let db = Store::open(dir.path()).unwrap();
    edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["protocol"] = json!("wireguard");
        cfg["traffic_obfuscation"] = json!(false);
        cfg["conn"]["host"] = json!("vpn.example.test");
        cfg["conn"]["known_key"] = json!("fixture-pin");
        cfg["conn"]["password"] = json!("password-private-fixture");
        Ok(())
    })
    .unwrap();
    (dir, db)
}

#[test]
fn restore_guard_blocks_remote_management_without_waiting_or_changing_keys() {
    let (dir, db) = fixture();
    let rt = Runtime::new(dir.path(), dir.path().join("missing"));
    let guard = rt.deployment_guard().unwrap();
    let before = read(&db).unwrap();
    assert_eq!(rt.deploy_profile(&db, None, &[])["ok"], false);
    assert!(rt.deploy_profiles(&db, &["awg0".into()], &[]).is_err());
    assert_eq!(before, read(&db).unwrap());
    drop(guard);
    assert!(rt.deployment_guard().is_ok());
}

#[test]
fn retry_preserves_persisted_keys_and_only_commits_confirmed_state() {
    let (_dir, db) = fixture();
    let mut sent = String::new();
    run(&db, None, |_, cfg, text, _| {
        assert_eq!(read(&db)?["servers"][0]["config"], *cfg);
        assert!(text.starts_with(MARKER));
        assert!(text.contains("AllowedIPs = 10.13.13.2/32"));
        assert!(!text.contains("0.0.0.0/0") && !text.contains("password-private-fixture"));
        assert!(!text.contains(cfg["peers"][0]["private_key"].as_str().unwrap()));
        sent = text.to_owned();
        Err(io::Error::other("fixture timeout"))
    })
    .unwrap_err();
    assert_eq!(read(&db).unwrap()["servers"][0]["config"]["deployed_at"], 0);
    run(&db, Some("awg0"), |_, _, text, _| {
        assert_eq!(text, sent);
        Ok(Backend::WireGuard)
    })
    .unwrap();
    let row = &read(&db).unwrap()["servers"][0];
    assert_eq!(row["config"]["native_vpn_tool"], "wg");
    assert_eq!(row["config"]["native_vpn_method"], "wireguard");
    assert!(row["config"]["deployed_at"].as_u64().unwrap() > 0);
    assert!(row["applied_config"].is_null());
}

#[test]
fn concurrent_edit_remains_pending_against_confirmed_snapshot() {
    let (_dir, db) = fixture();
    run(&db, None, |_, _, _, _| {
        edit_document(&db, |doc| {
            doc["servers"][0]["config"]["mtu"] = json!(1300);
            Ok(())
        })
        .map(|()| Backend::WireGuard)
    })
    .unwrap();
    let row = &read(&db).unwrap()["servers"][0];
    assert_eq!(row["config"]["mtu"], 1300);
    assert_eq!(row["applied_config"]["mtu"], 1420);
    assert_eq!(row["applied_config"]["native_vpn_tool"], "wg");
}

#[test]
fn foreign_profiles_addresses_and_lost_identities_fail_before_ssh() {
    let (_dir, db) = fixture();
    let row = read(&db).unwrap()["servers"][0].clone();
    run(&db, Some("missing"), |_, _, _, _| panic!("unknown server")).unwrap_err();
    for (field, value) in [
        ("enabled", json!(false)),
        ("protocol", json!("unknown")),
        ("install", json!("imported")),
        ("interface", json!("wg1;sh")),
        ("deployed_at", json!(42)),
        ("conn", json!({"host":"vpn.example.test"})),
    ] {
        let mut invalid = row.clone();
        invalid["config"][field] = value;
        assert!(prepare(&mut invalid).is_err(), "{field}");
    }
    let mut lost = row.clone();
    lost["applied_config"] = row["config"].clone();
    assert!(prepare(&mut lost).is_err());
    let mut good = row;
    prepare(&mut good).unwrap();
    let cfg = good["config"].clone();
    for addr in [
        "192.0.2.3/0",
        "239.1.1.1/24",
        "0.0.0.0/24",
        "::1/64",
        "255.255.255.255/32",
        "10.1.1.2/24\nPostUp = value",
    ] {
        let mut bad = cfg.clone();
        bad["address"] = json!(addr);
        assert!(render(&bad).is_err(), "{addr}");
    }
    let mut changed = cfg.clone();
    changed["peers"][0]["address"] = json!("192.0.2.99, 2001:db8::3/64");
    assert!(render(&changed)
        .unwrap()
        .contains("AllowedIPs = 192.0.2.99/32, 2001:db8::3/128"));
    changed["peers"][0]["address"] = cfg["address"].clone();
    assert!(render(&changed).is_err());
    changed = cfg.clone();
    changed["public_key"] = cfg["peers"][0]["public_key"].clone();
    assert!(render(&changed).is_err());
}

#[test]
fn go_server_config_keeps_the_server_identity_hooks_and_awg_extensions() {
    use sha2::{Digest, Sha256};
    let (_dir, db) = fixture();
    edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["protocol"] = "awg".into();
        cfg["traffic_obfuscation"] = true.into();
        cfg["wan_iface"] = "ens3".into();
        cfg["obf"]["jc"] = 6.into();
        Ok(())
    })
    .unwrap();
    let mut expected = String::new();
    run(&db, None, |_, cfg, text, old| {
        assert!(old.is_none());
        assert!(text.starts_with("[Interface]\nPrivateKey = "));
        assert!(text.contains("Jc = 6\n"));
        assert!(text.contains("-s 10.13.13.0/24 -o ens3 -j MASQUERADE"));
        assert!(text.ends_with("AllowedIPs = 10.13.13.2/32\n"));
        assert!(!text.contains(cfg["peers"][0]["private_key"].as_str().unwrap()));
        expected = text.to_owned();
        Ok(Backend::Userspace)
    })
    .unwrap();
    let active = &read(&db).unwrap()["servers"][0]["config"];
    assert_eq!(active["native_vpn_tool"], "awg");
    edit_document(&db, |doc| {
        let r = &mut doc["servers"][0];
        r["config"]
            .as_object_mut()
            .unwrap()
            .remove("native_vpn_tool");
        r["applied_config"] = r["config"].clone();
        r["config"]["mtu"] = 1300.into();
        Ok(())
    })
    .unwrap();
    run(&db, None, |_, _, text, old| {
        assert_eq!(
            old.unwrap().as_slice(),
            Sha256::digest(expected.as_bytes()).as_slice()
        );
        assert!(text.contains("MTU = 1300\n"));
        Ok(Backend::Userspace)
    })
    .unwrap();
    for value in ["en0;false", "$(hostname)", "eth0\nPostUp = value"] {
        let mut bad = active.clone();
        bad["wan_iface"] = value.into();
        assert!(render(&bad).is_err());
    }
}

#[test]
fn apt_keeps_the_wire_format_and_records_the_confirmed_backend() {
    let (_dir, db) = fixture();
    edit_document(&db, |doc| {
        let cfg = &mut doc["servers"][0]["config"];
        cfg["protocol"] = json!("awg");
        cfg["protocol_version"] = json!("2");
        cfg["traffic_obfuscation"] = json!(true);
        cfg["obf"] = json!({"jc":5});
        Ok(())
    })
    .unwrap();
    run(&db, None, |_, cfg, text, previous| {
        assert!(previous.is_none());
        assert_eq!(Backend::requested(cfg), Backend::Kernel);
        assert!(text.contains("Jc = 5\n") && text.contains("PostUp = "));
        Ok(Backend::Kernel)
    })
    .unwrap();
    let active = &read(&db).unwrap()["servers"][0]["config"];
    assert_eq!(active["native_vpn_tool"], "awg");
    assert_eq!(active["native_vpn_method"], "apt");
    assert_eq!(userspace::sync_tool(active).unwrap(), "awg-kernel");
    let mut legacy = active.clone();
    legacy.as_object_mut().unwrap().remove("native_vpn_method");
    assert_eq!(userspace::sync_tool(&legacy).unwrap(), "awg-auto");

    let mut fallback = active.clone();
    fallback["native_vpn_method"] = json!("userspace");
    assert_eq!(userspace::sync_tool(&fallback).unwrap(), "awg");
    assert_eq!(render(active).unwrap(), render(&fallback).unwrap());
    fallback["obf"]["random_trailers"] = json!(true);
    assert_eq!(Backend::requested(&fallback), Backend::Userspace);
    fallback["traffic_obfuscation"] = json!(false);
    assert_eq!(Backend::requested(&fallback), Backend::Kernel);
    assert!(!render(&fallback).unwrap().contains("RandomTrailers"));
    fallback["traffic_obfuscation"] = json!(true);
    fallback["obf"] = json!({});
    fallback["peers"][0]["keepalive_range"] = json!("25-35");
    assert_eq!(Backend::requested(&fallback), Backend::Userspace);
}
