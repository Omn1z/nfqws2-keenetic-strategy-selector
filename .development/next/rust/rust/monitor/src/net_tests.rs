use super::*;
use serde_json::{json, to_value};
use tempfile::tempdir;

const TCP: &str = "ipv4 2 tcp 6 1191 ESTABLISHED src=192.168.1.4 dst=192.0.2.10 sport=55555 dport=80 packets=6 bytes=815 src=192.0.2.10 dst=192.168.1.4 sport=80 dport=55555 packets=5 bytes=617 [ASSURED] [FASTNAT] slan";
const SYN: &str = "ipv4 2 tcp 6 30 SYN_SENT src=192.168.1.4 dst=198.51.100.2 sport=27000 dport=443 packets=2 bytes=120 [UNREPLIED] bytes=0 mac=02:AA:BB:00:11:22 slan";
const V6: &str = "ipv6 10 udp 17 30 src=fd00::1 dst=2001:db8::f sport=3000 dport=443 bytes=80 bytes=90 mac=02:AA:BB:00:11:22 slan";
const MAC: &str = "02:aa:bb:00:11:22";

fn write(root: &Path, subpath: &str, data: impl AsRef<[u8]>) {
    let path = root.join(subpath);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

#[test]
fn conntrack_preserves_original_tuple_and_separates_reply_counters() {
    let c = conn(TCP).unwrap();
    assert_eq!(
        to_value(&c).unwrap(),
        json!({
            "l3":"ipv4","proto":"tcp","state":"ESTABLISHED","ttl":1191,"src":"192.168.1.4","dst":"192.0.2.10",
            "sport":55555,"dport":80,"packets":6,"bytes":815,"reply_bytes":617,"assured":true,"fastnat":true,
            "unreplied":false,"mac":"","zone":"slan"
        })
    );
    let c = conn(SYN).unwrap();
    assert!(c.failing() && c.unreplied);
    assert_eq!(c.mac, MAC);
    assert!(!conn(V6).unwrap().failing());
    assert!(conn("ipv4 2 tcp 6 +4").is_none());
    assert!(conn("garbage line").is_none());
    let c = to_value(
        conn("ipv4 2 udp 17 3 src=invalid src=192.0.2.19 bytes=bad bytes=2 dport=+2").unwrap(),
    )
    .unwrap();
    assert_eq!((c["src"].as_str(), c["dst"].as_str()), (Some(""), Some("")));
    assert_eq!(
        (&c["bytes"], &c["reply_bytes"], &c["dport"]),
        (&json!(0), &json!(2), &json!(0))
    );
}

#[test]
fn views_merge_arp_dhcp_ndp_and_preserve_dashboard_field_contracts() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut monitor = NetworkMonitor::new(root.join("proc"), root);
    write(
        root,
        "proc/net/nf_conntrack",
        [
            TCP,
            SYN,
            V6,
            V6,
            "ipv4 2 icmp 1 5 src=192.168.1.8 dst=192.0.2.99 bytes=12 slan",
            "ipv4 2 udp 17 5 src=192.168.1.4 dst=224.0.0.251 [UNREPLIED] slan",
            "ipv4 2 udp 17 5 src=192.168.1.4 dst=203.0.113.10 swan",
            "invalid",
        ]
        .join("\n"),
    );
    write(root,"proc/net/arp","IP address HW type Flags HW address Mask Device\n192.168.1.4 0x1 0x2 02:AA:BB:00:11:22 * br-lan");
    write(
        root,
        "tmp/dhcp.leases",
        "0 02:AA:BB:00:11:22 192.168.1.4 tv *\n0 02:aa:bb:00:99:88 192.168.1.5 * *",
    );
    write(
        root,
        "var/dhcp.leases",
        "0 02:aa:bb:00:11:22 192.168.1.4 wrong *",
    );
    write(root, "proc/sys/net/netfilter/nf_conntrack_count", "150\n");
    write(root, "proc/sys/net/netfilter/nf_conntrack_max", "65536\n");
    write(
        root,
        "proc/net/netfilter/nfnetlink_queue",
        "broken\n200 80 9 1 2048 2 3 987654 1\n",
    );
    write(root,"proc/net/dev","Inter-| Receive | Transmit\n face |bytes packets\n lo: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n eth0: 111 2 3 4 5 6 7 8 999 8 11 12 13 14 15 16\n");
    monitor.ndp = Some((
        Instant::now(),
        HashMap::from([
            (MAC.to_string(), HashSet::from(["fe80::4".parse().unwrap()])),
            (
                "02:aa:bb:00:99:88".into(),
                HashSet::from(["fe80::5".parse().unwrap()]),
            ),
        ]),
    ));
    assert_eq!(monitor.connections().unwrap().count, 7);
    let devs = monitor.devices().unwrap().devices;
    assert_eq!(devs.len(), 3);
    assert_eq!(
        to_value(&devs[0]).unwrap(),
        json!({
            "ip":"192.168.1.4","ipv6":["fd00::1","fe80::4"],"mac":MAC,"hostname":"tv","iface":"br-lan",
            "total":4,"established":3,"failing":1,"bytes_up":1095,"bytes_down":797,
            "working":["192.0.2.10:80","[2001:db8::f]:443"],"failing_dsts":["198.51.100.2:443"]
        })
    );
    assert_eq!(devs[1].working, ["192.0.2.99"]);
    assert!(to_value(&devs[1]).unwrap().get("ipv6").is_none());
    assert_eq!(
        (
            devs[2].ip.as_str(),
            devs[2].hostname.as_str(),
            devs[2].total
        ),
        ("fe80::5", "", 0)
    );
    let data =
        to_value(monitor.dashboard(&["eth0".to_string()], 200, &root.join("absent"))).unwrap();
    assert_eq!(
        data["conns"],
        json!({"total":7,"failing":2,"by_proto":{"udp":4,"icmp":1,"tcp":2}})
    );
    assert_eq!(data["conntrack"], json!({"count":150,"max":65536}));
    assert_eq!(data["nfqws2_running"], true);
    assert_eq!(data["main_queue"], 200);
    assert_eq!(
        data["queues"],
        json!([{"queue":200,"portid":80,"queued":9,"copy_mode":1,"copy_range":2048,"queue_drop":2,"user_drop":3,"id_seq":987654}])
    );
    assert_eq!(
        data["wan"],
        json!([{"iface":"eth0","rx_bytes":111,"rx_packets":2,"tx_bytes":999,"tx_packets":8}])
    );
    assert_eq!(data["top_devices"][0], to_value(&devs[0]).unwrap());
    assert!(data.get("storage").is_none());
}

#[test]
fn dual_stack_device_counts_use_only_confirmed_lan_origins() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut monitor = NetworkMonitor::new(root.join("proc"), root);
    let addresses = |s: &[&str]| s.iter().map(|ip| ip.parse::<Ipv6Addr>().unwrap()).collect();
    let other = "02:aa:bb:00:99:88";
    monitor.ndp = Some((
        Instant::now(),
        HashMap::from([
            (
                MAC.into(),
                addresses(&["fd00::1", "2001:db8::1", "2001:db8::2", "fe80::1"]),
            ),
            (other.into(), addresses(&["2001:db8::2"])),
        ]),
    ));
    write(root,"proc/net/arp","IP address HW type Flags HW address Mask Device\n192.168.1.4 0x1 0x2 02:AA:BB:00:11:22 * br0\n");
    write(
        root,
        "tmp/dhcp.leases",
        "0 02:aa:bb:00:11:22 192.168.1.4 workstation *",
    );
    let v6 = |src: &str, attrs: &str| {
        format!(
            "ipv6 10 udp 17 9 src={src} dst=2001:db8:ffff::10 dport=53 bytes=100 bytes=33 {attrs}"
        )
    };
    let mut lines = vec![
        v6("fd00::1", ""),
        v6("2001:db8::1", ""),
        v6("2001:db8::2", ""), // duplicate NDP address across bridges
        v6("2001:db8::1", "swan"),
        v6("2001:db8::1", &format!("mac={other}")),
        v6("2001:db8:12::9", &format!("mac={MAC} slan")), // Keenetic confirmed LAN
        v6("2001:db8:12::10", &format!("mac={MAC}")),     // unknown source outside LAN
        v6("fe80::1", "slan"),
        v6("::1", "slan"),
        v6("::", "slan"),
        v6("ff02::1", "slan"),
    ];
    lines.push(TCP.into()); // v4 bridge is discovered after the IPv6 rows
    write(root, "proc/net/nf_conntrack", lines.join("\n"));
    let devices = monitor.devices().unwrap().devices;
    assert_eq!(devices.len(), 2);
    let main = devices.iter().find(|d| d.mac == MAC).unwrap();
    assert_eq!(
        (
            main.ip.as_str(),
            main.hostname.as_str(),
            main.iface.as_str()
        ),
        ("192.168.1.4", "workstation", "br0")
    );
    assert_eq!((main.total, main.bytes_up, main.bytes_down), (4, 1115, 716));
    assert_eq!(devices.iter().find(|d| d.mac == other).unwrap().total, 0);
    let dashboard = monitor.dashboard(&[], 0, root);
    assert_eq!(dashboard.conns.total, lines.len());
    assert_eq!(
        to_value(&dashboard.top_devices.unwrap()[0]).unwrap(),
        to_value(main).unwrap()
    );
}

#[test]
fn absent_and_oversized_conntrack_rows_discard_partial_snapshot() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut monitor = NetworkMonitor::new(root.join("proc"), root);
    assert_eq!(
        monitor.devices().unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    for oversized in [false, true] {
        if oversized {
            write(
                root,
                "proc/net/nf_conntrack",
                format!("{TCP}\n{}", "x".repeat(256 * 1024 + 1)),
            );
        }
        let error = monitor.connections().unwrap_err();
        assert_eq!(
            error.kind(),
            if oversized {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::NotFound
            }
        );
        let result = to_value(monitor.dashboard(&[], 200, &root.join("missing"))).unwrap();
        assert_eq!(
            result["conns"],
            json!({"total":0,"failing":0,"by_proto":{}})
        );
        assert_eq!(result["conntrack"], json!({"count":0,"max":0}));
        assert!(!result["nfqws2_running"].as_bool().unwrap());
        assert!(
            result["wan"].is_null()
                && result["queues"].is_null()
                && result["top_devices"].is_null()
        );
    }
    write(root, "proc/net/nf_conntrack", "");
    assert_eq!(
        to_value(monitor.connections().unwrap()).unwrap(),
        json!({"items":[],"count":0})
    );
    assert_eq!(
        to_value(monitor.devices().unwrap()).unwrap(),
        json!({"devices":[]})
    );
    assert_eq!(
        monitor.dashboard(&[], 1, root).top_devices.unwrap().len(),
        0
    );
}

#[test]
fn dashboard_retains_eight_highest_transfer_devices() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut monitor = NetworkMonitor::new(root.join("proc"), root);
    let rows: Vec<_> = (1..=12)
        .map(|i| format!("ipv4 2 udp 17 12 src=192.168.1.{i} dst=203.0.113.1 bytes=10 bytes={i}"))
        .collect();
    write(root, "proc/net/nf_conntrack", rows.join("\n"));
    let result = monitor.dashboard(&[], 0, root);
    let devs = result.top_devices.unwrap();
    assert_eq!(devs.len(), 8);
    assert_eq!((devs[0].bytes_down, devs[7].bytes_down), (12, 5));
    assert_eq!(result.conns.total, 12);
}

#[test]
fn connection_reader_stops_on_consumer_error_before_scanning_later_records() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "proc/net/nf_conntrack",
        format!("{TCP}\n{SYN}\n{}", "x".repeat(300_000)),
    );
    let monitor = NetworkMonitor::new(root.join("proc"), root);
    let mut count = 0;
    let error = monitor
        .connection_reader()
        .unwrap()
        .visit(|row| {
            assert_eq!(row.state, "ESTABLISHED");
            count += 1;
            Err(io::ErrorKind::BrokenPipe.into())
        })
        .unwrap_err();
    assert_eq!(count, 1);
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
