use super::*;
use std::{fs, path::PathBuf};
struct Fixtures(PathBuf);
impl Fixtures {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("nfqws2-trace-test-{}-{name}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixtures {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn only_identified_unicast_neighbors_of_lan_bridges_are_selected() {
    let f = Fixtures::new("peer");
    let root = &f.0;
    fs::create_dir_all(root.join("br0/bridge")).unwrap();
    let ip = "192.0.2.4".parse().unwrap();
    let row = "192.0.2.4 0x1 0x2 02:11:22:33:44:55 * br0";
    assert_eq!(device::from_arp(ip, row, root, &[]).unwrap().iface, "br0");
    for rejected in [
        row.replace("br0", "wan0"),
        row.replace("0x2", "0x0"),
        row.replace("02:", "ff:"),
        row.replace("192.0.2.4", "192.0.2.5"),
    ] {
        assert!(device::from_arp(ip, &rejected, root, &[]).is_none());
    }
    assert!(device::from_arp(ip, row, root, &["br0".into()]).is_none());
    let v6 = "fd00::4".parse().unwrap();
    let nd = "fd00::4 dev br0 lladdr 02:11:22:33:44:55 STALE";
    assert!(device::from_neighbor(v6, nd, root, &[]).is_some());
    assert!(device::from_neighbor(v6, &nd.replace("STALE", "FAILED"), root, &[]).is_none());
    for addr in ["0.0.0.0", "127.0.0.1", "ff02::1", "::1", "255.255.255.255"] {
        assert!(device::validate(addr.parse().unwrap()).is_err());
    }
}
#[test]
fn conntrack_trace_filters_other_devices_and_tracks_transitions() {
    let f = Fixtures::new("flows");
    let path = f.0.join("conntrack");
    let mut t = flows::Tracker::default();
    let ip = "192.0.2.4".parse().unwrap();
    let row="ipv4 2 tcp 6 120 SYN_SENT src=192.0.2.4 dst=198.51.100.2 sport=3333 dport=443 packets=1 bytes=60 [UNREPLIED] src=198.51.100.2 dst=192.0.2.4 packets=0 bytes=0";
    fs::write(
        &path,
        format!("{row}\n{}\n", row.replace("192.0.2.4", "192.0.2.5")),
    )
    .unwrap();
    let e = json!(t.sample(&path, ip, 0).unwrap());
    assert_eq!(e.as_array().unwrap().len(), 2);
    assert_eq!(e[0]["kind"], "new");
    assert_eq!(e[1]["kind"], "unreplied");
    fs::write(
        &path,
        row.replace("[UNREPLIED]", "[ASSURED]")
            .replace("bytes=0", "bytes=40"),
    )
    .unwrap();
    let e = json!(t.sample(&path, ip, 500).unwrap());
    assert_eq!(e[0]["kind"], "replied");
    fs::write(&path, "").unwrap();
    assert_eq!(json!(t.sample(&path, ip, 1000).unwrap())[0]["kind"], "gone");
    let result = json!(t.finish());
    assert_eq!(result.as_array().unwrap().len(), 1);
    assert_eq!(result[0]["max_bytes"], 100);
    assert_eq!(result[0]["samples"], 2);
    assert_eq!(result[0]["gone"], true);
}
