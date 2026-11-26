use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::{fs, path::PathBuf, time::Instant};
use tempfile::TempDir;
use tower::ServiceExt;

const ORIGINAL: &str = "00:11:22:33:44:50";
struct Fixture(PathBuf);
struct Ndm(Fixture);
impl Runner for Ndm {
    fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
        if Path::new(program).file_name().unwrap() == "ip" {
            return self.0.run(program, args, deadline);
        }
        let root = &self.0 .0;
        let ["-c", command] = args else {
            panic!("unexpected firmware command")
        };
        if *command == "show interface Bridge0" {
            let mac = fs::read_to_string(root.join("native"))?;
            let level = fs::read_to_string(root.join("level"))?;
            return Ok(format!("            id: Bridge0\n          type: Bridge\nsecurity-level: {level}\n        global: no\n           mac: {mac}"));
        }
        let mac = command
            .strip_prefix("interface Bridge0 mac address ")
            .expect("only native Bridge0");
        fs::write(root.join("native"), mac)?;
        if root.join("split-once").exists() {
            fs::remove_file(root.join("split-once"))?;
        } else {
            fs::write(root.join("sys/class/net/br0/address"), mac)?;
        }
        Ok(String::new())
    }
}
impl Runner for Fixture {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        assert_eq!(Path::new(program).file_name().unwrap(), "ip");
        match args {
            ["-4" | "-6", "neigh", "show"] => {
                Ok(fs::read_to_string(self.0.join("neighbors")).unwrap_or_default())
            }
            ["link", "set", "dev", name @ ("br0" | "br2" | "br3"), "address", mac] => {
                fs::write(self.0.join("sys/class/net").join(name).join("address"), mac)?;
                if fs::read_to_string(self.0.join("fail-once"))
                    .is_ok_and(|n| n.is_empty() || n == *name)
                {
                    fs::remove_file(self.0.join("fail-once"))?;
                    return Err(io::Error::other("simulated interrupted command"));
                }
                Ok(String::new())
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
fn topology(root: &Path) {
    for (idx, name, mac) in [(4, "br0", ORIGINAL), (5, "br1", "00:11:22:33:44:60")] {
        let iface = root.join("sys/class/net").join(name);
        fs::create_dir_all(iface.join("bridge")).unwrap();
        fs::write(iface.join("address"), mac).unwrap();
        fs::write(iface.join("ifindex"), idx.to_string()).unwrap();
        fs::write(iface.join("flags"), "0x1003").unwrap();
    }
    fs::create_dir_all(root.join("proc/net")).unwrap();
    fs::write(
        root.join("proc/net/route"),
        "Iface Destination Gateway Flags\nbr1 00000000 01020304 0003\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("sbin")).unwrap();
    let cmd = root.join("sbin/ip");
    fs::write(&cmd, b"fixture").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(cmd, fs::Permissions::from_mode(0o755)).unwrap();
    }
}
fn setup() -> (TempDir, Store, Service<Fixture>) {
    let dir = tempfile::tempdir().unwrap();
    topology(dir.path());
    let store = Store::open(dir.path().join("data")).unwrap();
    let svc = Service {
        device: device::Device::new(dir.path(), Fixture(dir.path().into())),
    };
    (dir, store, svc)
}

#[test]
fn shared_ipv6_prefix_grants_local_access_only_on_the_confirmed_bridge() {
    let (dir, _, service) = setup();
    let path = dir.path().join("proc/net/if_inet6");
    let router = "2001:db8:17::1".parse().unwrap();
    let client = "2001:db8:17::42".parse().unwrap();
    let other = "2001:db8:18::42".parse().unwrap();
    let lan = "20010db8001700000000000000000001 04 40 00 80 br0\n";
    fs::write(&path, lan).unwrap();
    assert!(service.same_ipv6_lan(&[], router, client));
    assert!(!service.same_ipv6_lan(&[], router, other));
    assert!(!service.same_ipv6_lan(&["br0".into()], router, client));
    fs::write(&path, lan.replace("04 40 00 80 br0", "05 40 00 80 br1")).unwrap();
    assert!(!service.same_ipv6_lan(&[], router, client));
    fs::write(&path, lan.replace("04 40 00 80 br0", "0b 40 00 80 br0")).unwrap();
    assert!(!service.same_ipv6_lan(&[], router, client));
    fs::write(&path, lan.replace("00 80", "00 40")).unwrap();
    assert!(!service.same_ipv6_lan(&[], router, client));
    fs::write(
        &path,
        format!(
            "{lan}{}",
            lan.replace("04 40", "05 40").replace("br0", "br1")
        ),
    )
    .unwrap();
    assert!(!service.same_ipv6_lan(&[], router, client));
}
#[test]
fn keenetic_requires_private_identity_and_restores_partially_applied_native_address() {
    let (dir, store, _) = setup();
    let ndmc = dir.path().join("sbin/ndmc");
    fs::copy(dir.path().join("sbin/ip"), &ndmc).unwrap();
    fs::write(dir.path().join("native"), ORIGINAL).unwrap();
    fs::write(dir.path().join("level"), "public").unwrap();
    let svc = Service {
        device: device::Device::new(dir.path(), Ndm(Fixture(dir.path().into()))),
    };
    let mac = random_mac("02").unwrap();
    let cfg = Config {
        enabled: true,
        mac: mac.clone(),
        ..Default::default()
    };
    assert!(svc
        .change(&store, &[], journal::Change::Config(cfg.clone()))
        .is_err());
    fs::write(dir.path().join("level"), "private").unwrap();
    fs::write(dir.path().join("split-once"), "").unwrap();
    assert!(svc
        .change(&store, &[], journal::Change::Config(cfg.clone()))
        .is_err());
    assert_eq!(
        fs::read_to_string(dir.path().join("native")).unwrap(),
        ORIGINAL
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("sys/class/net/br0/address")).unwrap(),
        ORIGINAL
    );
    assert!(receipt(&store).unwrap().pending.is_none());
    svc.change(&store, &[], journal::Change::Config(cfg))
        .unwrap();
    assert_eq!(svc.view(&store, &[]).unwrap()["active"], true);
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("native")).unwrap(),
        ORIGINAL
    );
}
#[test]
fn crash_recovery_uses_committed_config_and_never_overwrites_a_foreign_address() {
    let (dir, store, svc) = setup();
    let new = random_mac("").unwrap();
    let cfg = Config {
        enabled: true,
        mac: new.clone(),
        ..Default::default()
    };
    let base = dir.path().join("data");
    let address = dir.path().join("sys/class/net/br0/address");
    let intention = json!({"issued":new,"pending":{"name":"br0","index":4,"before":ORIGINAL,"after":new,"config":cfg,"next":{"name":"br0","index":4,"original":ORIGINAL,"assigned":new}}});
    let pending = || {
        store
            .transaction(|tx| tx.save_runtime(RECEIPT, &intention))
            .unwrap()
    };
    pending();
    fs::write(&address, "02:01:02:03:04:05").unwrap();
    assert!(svc.restore(&store, &[]).is_err());
    assert!(receipt(&store).unwrap().pending.is_some());
    fs::write(&address, &new).unwrap();
    svc.restore(&store, &[]).unwrap();
    assert_eq!(fs::read_to_string(&address).unwrap(), ORIGINAL);
    assert!(receipt(&store).unwrap().leases.is_empty());
    pending();
    fs::write(base.join(FILE), json!({"config":cfg}).to_string()).unwrap();
    svc.restore(&store, &[]).unwrap();
    assert_eq!(fs::read_to_string(&address).unwrap(), new);
    assert!(receipt(&store).unwrap().pending.is_none());
    assert!(!receipt(&store).unwrap().leases.is_empty());
}
#[test]
fn generated_local_address_and_enabled_profile_survive_restart_then_restore_original() {
    let (dir, store, svc) = setup();
    assert!(random_mac("00:18:82").unwrap().starts_with("00:18:82:"));
    let mac = random_mac("06:12").unwrap();
    assert!(mac.starts_with("06:12:"));
    let mut cfg = Config {
        mac: mac.clone(),
        enabled: true,
        ifaces: vec!["br1".into()],
        ..Default::default()
    };
    assert!(svc
        .change(&store, &[], journal::Change::Config(cfg.clone()))
        .is_err());
    cfg.ifaces.clear();
    let mut unused = cfg.clone();
    unused.mac = "00:11:22:33:44:60".into();
    assert!(svc
        .change(&store, &[], journal::Change::Config(unused))
        .is_err());
    fs::write(
        dir.path().join("neighbors"),
        format!("fe80::1 dev br0 lladdr {mac} REACHABLE"),
    )
    .unwrap();
    assert!(svc
        .change(&store, &[], journal::Change::Config(cfg.clone()))
        .is_err());
    fs::remove_file(dir.path().join("neighbors")).unwrap();
    svc.change(&store, &[], journal::Change::Config(cfg))
        .unwrap();
    let address = dir.path().join("sys/class/net/br0/address");
    assert_eq!(fs::read_to_string(&address).unwrap(), mac);
    assert_eq!(svc.view(&store, &[]).unwrap()["active"], true);
    fs::write(&address, ORIGINAL).unwrap();
    svc.restore(&store, &[]).unwrap();
    assert_eq!(fs::read_to_string(&address).unwrap(), mac);
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(fs::read_to_string(&address).unwrap(), ORIGINAL);
    assert!(!saved(&store).unwrap().config.enabled);
    assert!(receipt(&store).unwrap().leases.is_empty());
}
#[test]
fn legacy_bridge_can_be_disabled_after_upgrading() {
    let (dir, store, svc) = setup();
    let address = dir.path().join("sys/class/net/br0/address");
    let assigned = "00:11:22:33:44:60";
    fs::write(&address, assigned).unwrap();
    store
        .transaction(|tx| {
            tx.save(
                FILE,
                &json!({
                    "config": {"enabled": true, "mac": assigned, "ifaces": ["br0"]},
                    "applied_at": 17, "original_macs": {"br0": ORIGINAL}
                }),
            )
        })
        .unwrap();
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(fs::read_to_string(&address).unwrap(), ORIGINAL);
    assert!(!saved(&store).unwrap().config.enabled);
    assert!(receipt(&store).unwrap().leases.is_empty());
}

#[test]
fn partial_command_is_undone_and_foreign_edits_and_legacy_originals_are_preserved() {
    let (dir, store, svc) = setup();
    let mac = random_mac("").unwrap();
    let cfg = Config {
        mac: mac.clone(),
        enabled: true,
        ..Default::default()
    };
    fs::write(dir.path().join("fail-once"), "").unwrap();
    assert!(svc
        .change(&store, &[], journal::Change::Config(cfg.clone()))
        .is_err());
    let address = dir.path().join("sys/class/net/br0/address");
    assert_eq!(fs::read_to_string(&address).unwrap(), ORIGINAL);
    assert!(receipt(&store).unwrap().pending.is_none());
    svc.change(&store, &[], journal::Change::Config(cfg))
        .unwrap();
    fs::write(&address, "02:01:02:03:04:05").unwrap();
    assert!(svc
        .change(&store, &[], journal::Change::Enable(false))
        .is_err());
    assert_eq!(fs::read_to_string(&address).unwrap(), "02:01:02:03:04:05");
    let (_dir, store, svc) = setup();
    store.transaction(|tx|tx.save(FILE,&json!({"config":{"enabled":true,"mac":ORIGINAL,"ifaces":null,"vendor_id":"legacy","prefix":"00:11:22"},"applied_at":18,"original_macs":{"br0":"legacy-private-field"}}))).unwrap();
    let v = svc.view(&store, &[]).unwrap();
    assert_eq!(v["active"], true);
    assert_eq!(v["applied_at"], 18);
    assert!(!v.to_string().contains("legacy-private-field"));
    assert!(svc
        .change(&store, &[], journal::Change::Enable(false))
        .is_err());
}
#[tokio::test]
async fn normal_routes_report_missing_and_invalid_state_and_persist_disabled_config() {
    let dir = tempfile::tempdir().unwrap();
    topology(dir.path());
    let cfg = nfqws2_config::Config {
        data_dir: dir.path().join("data").display().to_string(),
        ..Default::default()
    };
    let s = crate::http::AppState::open(cfg, dir.path(), true).unwrap();
    let app = crate::http::router(s.clone());
    async fn call(app: &Router, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let method = if body.is_some() { "POST" } else { "GET" };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    let (code, v) = call(&app, "/api/arp-spoofing", None).await;
    assert_eq!(code, 200);
    assert_eq!(v["active"], false);
    assert_eq!(v["config"]["ifaces"], json!([]));
    assert_eq!(v["suggested_ifaces"], json!(["br0"]));
    let (code, v) = call(
        &app,
        "/api/arp-spoofing/generate",
        Some(json!({"prefix":"02"})),
    )
    .await;
    assert_eq!(code, 200);
    let mac = &v["mac"];
    let (code, v) = call(
        &app,
        "/api/arp-spoofing/config",
        Some(json!({"mac":mac,"enabled":false})),
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(&v["config"]["mac"], mac);
    assert_eq!(
        call(
            &app,
            "/api/arp-spoofing/enabled",
            Some(json!({"enabled":false}))
        )
        .await
        .0,
        200
    );
    fs::write(dir.path().join("data").join(FILE), b"{").unwrap();
    assert_eq!(call(&app, "/api/arp-spoofing", None).await.0, 500);
}

fn add_bridge(root: &Path, name: &str, index: u32, mac: &str) {
    let dir = root.join("sys/class/net").join(name);
    fs::create_dir_all(dir.join("bridge")).unwrap();
    fs::write(dir.join("ifindex"), index.to_string()).unwrap();
    fs::write(dir.join("flags"), "0x1003").unwrap();
    fs::write(dir.join("address"), mac).unwrap();
}
fn mac_on(root: &Path, name: &str) -> String {
    fs::read_to_string(root.join("sys/class/net").join(name).join("address")).unwrap()
}
const OTHER: &str = "00:20:30:40:50:62";
const THIRD: &str = "00:20:30:40:50:63";
const ASSIGNED: &str = "00:18:82:AA:BB:CC";
fn explicit(names: &[&str]) -> Config {
    Config {
        enabled: true,
        mac: ASSIGNED.to_string(),
        ifaces: names.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}
#[test]
fn selects_and_switches_multiple_lan_bridges_and_restores_each_original() {
    let (dir, store, svc) = setup();
    let root = dir.path();
    add_bridge(root, "br2", 6, OTHER);
    add_bridge(root, "br3", 7, THIRD);
    svc.change(
        &store,
        &[],
        journal::Change::Config(explicit(&["br2", "br0", "br2"])),
    )
    .unwrap();
    assert_eq!(mac_on(root, "br0"), ASSIGNED);
    assert_eq!(mac_on(root, "br2"), ASSIGNED);
    assert_eq!(mac_on(root, "br3"), THIRD);
    assert_eq!(
        saved(&store).unwrap().original_macs,
        BTreeMap::from([
            ("br0".into(), ORIGINAL.into()),
            ("br2".into(), OTHER.into())
        ])
    );
    svc.change(
        &store,
        &[],
        journal::Change::Config(explicit(&["br2", "br3"])),
    )
    .unwrap();
    assert_eq!(mac_on(root, "br0"), ORIGINAL);
    assert_eq!(mac_on(root, "br2"), ASSIGNED);
    assert_eq!(mac_on(root, "br3"), ASSIGNED);
    assert_eq!(mac_on(root, "br1"), "00:11:22:33:44:60");
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(mac_on(root, "br2"), OTHER);
    assert_eq!(mac_on(root, "br3"), THIRD);
    assert!(saved(&store).unwrap().original_macs.is_empty());
}
#[test]
fn automatic_selection_refresh_and_partial_rollback_preserve_foreign_devices() {
    let (dir, store, svc) = setup();
    let root = dir.path();
    add_bridge(root, "br2", 6, OTHER);
    fs::write(root.join("fail-once"), "br2").unwrap();
    assert!(svc
        .change(&store, &[], journal::Change::Config(explicit(&[])))
        .is_err());
    assert_eq!(mac_on(root, "br0"), ORIGINAL);
    assert_eq!(mac_on(root, "br2"), OTHER);
    assert!(receipt(&store).unwrap().pending.is_none());
    svc.change(&store, &[], journal::Change::Config(explicit(&[])))
        .unwrap();
    add_bridge(root, "br3", 7, THIRD);
    add_bridge(root, "lan0", 12, "00:00:01:02:03:04");
    fs::create_dir(root.join("sys/class/net/lan0/master")).unwrap();
    assert_eq!(svc.view(&store, &[]).unwrap()["active"], false);
    svc.restore(&store, &[]).unwrap();
    assert_eq!(mac_on(root, "br3"), ASSIGNED);
    assert_eq!(mac_on(root, "lan0"), "00:00:01:02:03:04");
    let state = root.join("data").join(FILE);
    let committed = fs::read(&state).unwrap();
    let meta = fs::metadata(&state).unwrap().modified().unwrap();
    svc.restore(&store, &[]).unwrap();
    assert_eq!(fs::metadata(&state).unwrap().modified().unwrap(), meta);
    assert_eq!(fs::read(&state).unwrap(), committed);
    fs::write(root.join("sys/class/net/br3/address"), THIRD).unwrap();
    fs::write(root.join("sys/class/net/br1/address"), ASSIGNED).unwrap();
    assert!(svc.restore(&store, &[]).is_err());
    assert_eq!(mac_on(root, "br3"), THIRD);
    assert!(receipt(&store).unwrap().pending.is_none());
    fs::write(root.join("sys/class/net/br1/address"), "00:11:22:33:44:60").unwrap();
    fs::write(
        root.join("neighbors"),
        format!("192.0.2.7 dev br3 lladdr {ASSIGNED} STALE"),
    )
    .unwrap();
    assert!(svc.restore(&store, &[]).is_err());
    assert_eq!(mac_on(root, "br3"), THIRD);
    fs::remove_file(root.join("neighbors")).unwrap();
    svc.restore(&store, &[]).unwrap();
    fs::write(root.join("sys/class/net/br2/ifindex"), "100").unwrap();
    assert!(svc
        .change(&store, &[], journal::Change::Enable(false))
        .is_err());
    assert_eq!(mac_on(root, "br0"), ASSIGNED);
    assert_eq!(mac_on(root, "br2"), ASSIGNED);
}
#[test]
fn automatically_adopts_multiple_running_go_bridges_and_repairs_after_restart() {
    let (dir, store, svc) = setup();
    let root = dir.path();
    add_bridge(root, "br2", 6, OTHER);
    fs::write(root.join("sys/class/net/br0/address"), ASSIGNED).unwrap();
    store.transaction(|tx|tx.save(FILE,&json!({"config":{"enabled":true,"mac":ASSIGNED,"ifaces":null},"applied_at":17,"original_macs":{"br0":ORIGINAL,"br2":OTHER}}))).unwrap();
    svc.restore(&store, &[]).unwrap();
    assert_eq!(mac_on(root, "br2"), ASSIGNED);
    assert_eq!(receipt(&store).unwrap().leases.len(), 2);
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(mac_on(root, "br0"), ORIGINAL);
    assert_eq!(mac_on(root, "br2"), OTHER);
}
#[test]
fn pending_batch_with_matching_config_and_distinct_membership_recovers_both_directions() {
    let (dir, store, svc) = setup();
    let root = dir.path();
    add_bridge(root, "br2", 6, OTHER);
    let cfg = explicit(&[]);
    let make_lease = |name: &str, index: u32, original: &str| json!({"name":name,"index":index,"original":original,"assigned":ASSIGNED});
    let make_op = |name: &str, index: u32, original: &str| json!({"name":name,"index":index,"original":original,"before":original,"after":ASSIGNED});
    let pending = json!({"leases":{"br0":make_lease("br0",4,ORIGINAL)},"pending":{"config":cfg,"ops":[make_op("br0",4,ORIGINAL),make_op("br2",6,OTHER)],"next":{"br0":make_lease("br0",4,ORIGINAL),"br2":make_lease("br2",6,OTHER)}}});
    for committed in [false, true] {
        let mut marks = BTreeMap::from([("br0", ORIGINAL)]);
        if committed {
            marks.insert("br2", OTHER);
        }
        let state = json!({"config":cfg,"original_macs":marks});
        store
            .transaction(|tx| {
                tx.save(FILE, &state)?;
                tx.save_runtime(RECEIPT, &pending)
            })
            .unwrap();
        fs::write(root.join("sys/class/net/br0/address"), ASSIGNED).unwrap();
        fs::write(
            root.join("sys/class/net/br2/address"),
            if committed { OTHER } else { ASSIGNED },
        )
        .unwrap();
        // An explicit disable following recovery must read the resolved ownership set.
        svc.change(&store, &[], journal::Change::Enable(false))
            .unwrap();
        assert_eq!(mac_on(root, "br0"), ORIGINAL);
        assert_eq!(mac_on(root, "br2"), OTHER);
        assert!(receipt(&store).unwrap().pending.is_none());
    }
}
#[test]
fn vendor_catalog_and_manual_addresses_follow_go_formats() {
    let (dir, store, svc) = setup();
    let view = svc.view(&store, &[]).unwrap();
    assert_eq!(view["config"]["vendor_id"], "huawei");
    assert_eq!(view["config"]["prefix"], "00:18:82");
    assert_eq!(view["vendors"].as_array().unwrap().len(), 13);
    for vendor in vendors::CATALOG {
        for p in vendor.prefixes {
            assert!(random_mac(p).unwrap().starts_with(p));
        }
    }
    assert!(random_mac("64-6e-ea").unwrap().starts_with("64:6E:EA:"));
    for p in ["FF", "01:23", "12:3456:78", "0", "AB:00:00:01"] {
        assert!(random_mac(p).is_err());
    }
    let mut cfg = explicit(&["br0"]);
    cfg.mac = "0201.0203.0405".into();
    cfg.prefix = "06".into();
    svc.change(&store, &[], journal::Change::Config(cfg))
        .unwrap();
    assert_eq!(mac_on(dir.path(), "br0"), "02:01:02:03:04:05");
    assert_eq!(saved(&store).unwrap().config.vendor_id, "custom");
}

#[test]
fn arp_announcement_uses_only_os_reported_ipv4_on_the_verified_bridge() {
    struct Announcements(Fixture, std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>);
    impl Runner for Announcements {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            match (
                Path::new(program).file_name().unwrap().to_str().unwrap(),
                args,
            ) {
                ("arping", _) => {
                    self.1
                        .lock()
                        .unwrap()
                        .push(args.iter().map(|s| s.to_string()).collect());
                    Ok(String::new())
                }
                ("ip", ["-o", "-4", "addr", "show", "dev", "br0"]) => Ok([
                    "4: br0 inet 192.0.2.1/24 brd 192.0.2.255 scope global br0",
                    "4: br0 inet 192.0.2.1/24 scope global br0",
                    "4: br0 inet 192.0.2.2/32 scope global secondary br0",
                    "5: br0 inet 198.51.100.1/24 scope global br0",
                    "4: br1 inet 198.51.100.2/24 scope global br1",
                    "4: br0 inet6 2001:db8::1/64 scope global",
                    "4: br0 inet 224.0.0.1/32 scope global",
                    "4: br0 inet 198.51.100.3/99 scope global",
                ]
                .join("\n")),
                _ => self.0.run(program, args, deadline),
            }
        }
    }
    let (dir, store, _) = setup();
    fs::copy(dir.path().join("sbin/ip"), dir.path().join("sbin/arping")).unwrap();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let svc = Service {
        device: device::Device::new(
            dir.path(),
            Announcements(Fixture(dir.path().into()), captured.clone()),
        ),
    };
    svc.change(&store, &[], journal::Change::Config(explicit(&["br0"])))
        .unwrap();
    let expected: Vec<Vec<String>> = ["192.0.2.1", "192.0.2.2"]
        .into_iter()
        .map(|ip| {
            ["-q", "-U", "-c", "2", "-I", "br0", "-s", ip, ip]
                .into_iter()
                .map(String::from)
                .collect()
        })
        .collect();
    assert_eq!(*captured.lock().unwrap(), expected);
    captured.lock().unwrap().clear();
    svc.restore(&store, &[]).unwrap();
    assert!(captured.lock().unwrap().is_empty());
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(*captured.lock().unwrap(), expected);
}

#[test]
fn stored_port_selection_resolves_to_its_own_lan_bridge_and_excludes_wan_masters() {
    let (dir, store, svc) = setup();
    let root = dir.path();
    let original_port = "00:20:01:01:01:01";
    add_bridge(root, "eth4", 13, original_port);
    fs::create_dir_all(root.join("sys/class/net/br0/brif/eth4")).unwrap();
    let config = explicit(&["eth4"]);
    assert!(svc
        .change(
            &store,
            &["eth4".into()],
            journal::Change::Config(config.clone())
        )
        .is_err());
    svc.change(&store, &[], journal::Change::Config(config))
        .unwrap();
    assert_eq!(mac_on(root, "br0"), ASSIGNED);
    assert_eq!(mac_on(root, "eth4"), original_port);
    assert_eq!(svc.view(&store, &[]).unwrap()["active"], true);
    assert!(saved(&store).unwrap().original_macs.contains_key("br0"));
    svc.change(&store, &[], journal::Change::Enable(false))
        .unwrap();
    assert_eq!(mac_on(root, "br0"), ORIGINAL);
}
