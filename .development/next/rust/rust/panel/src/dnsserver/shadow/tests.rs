use super::*;
use nfqws2_router_command::Runner;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

#[tokio::test]
async fn active_inform_requires_live_wan_proof_before_starting_a_probe() {
    struct ChangedWan(AtomicUsize);
    impl Source for ChangedWan {
        fn read(&self, _: &[discovery::History]) -> io::Result<discovery::Evidence> {
            let mut evidence = discovery::Evidence::fixture(Vec::new());
            let key = "ip=198.51.100.10|route=eth3/198.51.100.1";
            let client = "198.51.100.10".parse().unwrap();
            evidence.wan_key = key.into();
            evidence.inform.wan_ips.push(client);
            evidence.inform.owners.push(inform::state::Wan {
                key: key.into(),
                iface: "ISP".into(),
                device: "eth3".into(),
                index: 5,
                mac: [2, 0, 0, 0, 0, 1],
                client,
            });
            Ok(evidence)
        }
        fn confirm_inform(&self, owner: &inform::state::Wan, deadline: Instant) -> bool {
            assert_eq!(owner.iface, "ISP");
            assert!(deadline > Instant::now());
            self.0.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
    let changed = Arc::new(ChangedWan(AtomicUsize::new(0)));
    let mut env = Environment::new(Vec::new());
    env.source = changed.clone();
    env.diagnostics.set(true);
    let session = Session::fixture(
        &json!({"enabled":true,"domains":[{"domain":"example.test"}]}),
        Arc::new(env),
    )
    .unwrap();
    assert_eq!(
        session.discover(false).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(changed.0.load(Ordering::Relaxed), 1);
    let status = session.status();
    assert_eq!(status["servers"], json!([]));
    let diagnostics = &status["diagnostics"];
    assert_eq!(diagnostics["app_version"], crate::VERSION);
    assert_eq!(diagnostics["in_progress"], false);
    assert!(diagnostics["attempts"][0]["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["stage"] != "dhcp.start"));
}
#[test]
fn patterns_normalize_and_match_real_label_boundaries() {
    let mut v = json!({"enabled":true,"servers":["127.0.0.1"],"domains":[{"domain":"РФ"},{"domain":".рф"},{"domain":"*.vk.*"},{"domain":"*.net.*.zone"}]});
    normalize(&mut v).unwrap();
    assert_eq!(v["servers"], json!([]));
    assert_eq!(v["domains"].as_array().unwrap().len(), 3);
    let m = Matcher::compile(&v).unwrap();
    for s in [
        "xn--p1ai",
        "a.xn--p1ai",
        "vk.ru",
        "www.vk.kz",
        "a.net.b.zone",
    ] {
        assert!(m.matches(s));
    }
    for s in [
        "vk",
        "evilvk.ru",
        "vk.org.example",
        "net.zone",
        "net.a.b.zone",
    ] {
        assert!(!m.matches(s));
    }
    for d in ["*", "*.*", "a*.com", "foo..bar"] {
        v["domains"] = json!([{"domain":d}]);
        assert!(normalize(&mut v).is_err());
    }
}
struct Mock;
struct Script<F>(F);
impl<F: Fn(&str, &[&str]) -> io::Result<String> + Send + Sync> Runner for Script<F> {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        (self.0)(program, args)
    }
}
impl Runner for Mock {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        Ok(match (program,args){
            ("ip",_)=>"default via 192.0.2.1 dev eth9",
            ("ubus",["call","network.interface","dump"])=>r#"{"interface":[{"interface":"wan","proto":"dhcp","up":true,"l3_device":"eth9","dns-server":["192.0.2.20"],"inactive":{"dns-server":["192.0.2.53","::1","192.0.2.2","::ffff:192.0.2.53"]}},{"interface":"vpn","proto":"wireguard","up":true,"l3_device":"eth9","dns-server":["10.0.0.1"]}]}"#,
            ("ndmc",["-c","show ip name-server"])=>"server:\naddress: 192.0.2.53\nservice: DHCP client\ninterface: ISP\nserver-https:\naddress: 192.0.2.99\nservice: DHCP client\ninterface: ISP\nserver:\naddress: 10.0.0.45\nservice: DHCP client\ninterface: Bridge0\nserver:\naddress: 192.0.2.2\nservice: DHCP client\ninterface: ISP",
            ("ndmc",["-c","show interface ISP"])=>"connected: yes\naddress: 192.0.2.2",
            _=>return Err(io::ErrorKind::Unsupported.into())
        }.into())
    }
}
#[test]
fn supported_firmware_discovery_requires_current_wan_ownership_and_peer_metadata() {
    let hosts = vec![
        ("eth9".into(), "192.0.2.2".parse().unwrap()),
        ("br-lan".into(), "10.0.0.45".parse().unwrap()),
    ];
    let want = vec![Peer {
        expires: None,
        device: "eth9".into(),
        addr: "192.0.2.53:53".parse().unwrap(),
    }];
    assert_eq!(
        discovery::discover(&Mock, true, &["wan".into()], &hosts).unwrap(),
        want
    );
    assert_eq!(
        discovery::discover(&Mock, false, &["eth9".into()], &hosts).unwrap(),
        want
    );
    assert!(discovery::discover(&Mock, false, &["eth3".into()], &hosts).is_err());
}
struct Fixture {
    count: AtomicUsize,
    peer: Option<Peer>,
}
impl Source for Fixture {
    fn read(&self, _: &[discovery::History]) -> io::Result<discovery::Evidence> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.peer
            .clone()
            .map(|p| discovery::Evidence::fixture(vec![p]))
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
}
#[tokio::test]
async fn provider_discovery_udp_truncation_tcp_fallback_and_diagnostics() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let fixture = Arc::new(Fixture {
        peer: Some(Peer {
            expires: None,
            device: String::new(),
            addr,
        }),
        count: AtomicUsize::new(0),
    });
    let env = Arc::new(Environment {
        source: fixture.clone(),
        diagnostics: Default::default(),
        renewal: renew::Renewal::fixture(true),
        observer: Default::default(),
        leases: None,
        inform: Default::default(),
    });
    env.diagnostics.set(true);
    let cfg = json!({"enabled":true,"domains":[{"domain":"test","include_subdomains":true}]});
    let session = Session::fixture(&cfg, env.clone()).unwrap();
    let q = nfqws2_dns::build_query("sample.test", 1, 9).unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, client) = udp.recv_from(&mut buf).await.unwrap();
        let mut truncated = nfqws2_dns::response_error(&buf[..n], 0);
        truncated[2] |= 2;
        udp.send_to(&truncated, client).await.unwrap();
        let (mut socket, _) = tcp.accept().await.unwrap();
        let n = socket.read_u16().await.unwrap();
        let mut q = vec![0; n as usize];
        socket.read_exact(&mut q).await.unwrap();
        let mut r = nfqws2_dns::response_error(&q, 0);
        r[7] = 1;
        r.extend([192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 11]);
        socket.write_u16(r.len() as u16).await.unwrap();
        socket.write_all(&r).await.unwrap();
    });
    let (wire, server) = session
        .provider(
            &q,
            Duration::from_secs(3),
            &Semaphore::new(1),
            |_, _, error| {
                panic!("unexpected Shadow DNS attempt failure: {error}");
            },
        )
        .await
        .unwrap();
    assert_eq!(&wire[..2], &[0, 9]);
    assert_eq!(
        nfqws2_dns::first_ipv4(&wire).unwrap().to_string(),
        "192.0.2.11"
    );
    assert_eq!(server, addr.to_string());
    task.await.unwrap();
    let status = session.status();
    assert_eq!(status["fallback_active"], false);
    assert_eq!(
        status["diagnostics"]["attempts"].as_array().unwrap().len(),
        1
    );
    assert!(!status.to_string().contains("sample.test"));
    let request = session.renewal_request().unwrap();
    let resolved = request.already_resolved().await.unwrap();
    assert_eq!(resolved["status"], "resolved");
    assert_eq!(resolved["device"], "");
    assert_eq!(resolved["interface"], "");
    assert_eq!(session.status()["renewal_available"], true);
    drop(request);
    assert_eq!(fixture.count.load(Ordering::SeqCst), 2);
    env.diagnostics.set(false);
    assert_eq!(session.status()["diagnostics"]["attempts"], json!([]));
}
#[test]
fn ignored_dns_requires_a_current_matching_dhcp_ack_and_expires() {
    let log="I [Oct  3 01:15:13] ndhcpc: GigabitEthernet1: received ACK for 192.168.0.10\n  from 192.168.0.1 lease 86400 sec.\nI [Oct  3 01:15:13] ndm: Dhcp::Client: obtained IP address 192.168.0.10/24.\nW [Oct  3 01:15:13] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is\n ignored.\nW [Oct  3 01:15:14] ndm: Dns::InterfaceSpecific: name server 203.0.113.53 is ignored.";
    let now = leases::parse_clock("2026-10-03T01:16:13+0300").unwrap();
    let result = leases::parse(log, now);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].remaining, Duration::from_secs(86340));
    assert_eq!(
        result[0]
            .servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["192.0.2.53"]
    );
    assert!(leases::parse(log, now + time::Duration::days(2)).is_empty());
    assert!(leases::parse(&log.replace("192.168.0.10/24", "192.168.0.11/24"), now).is_empty());
    assert!(leases::parse(
        &format!("{log}\nI [Oct  3 01:15:14] ndhcpc: GigabitEthernet1: received NAK"),
        now
    )
    .is_empty());
    for matching in [true, false] {
        let firmware = Script(|program: &str, args: &[&str]| {
            Ok(match (program, args) {
                ("ip", _) => "default dev eth0",
                ("ndmc", ["-c", "show ip name-server"]) => "",
                ("ndmc", ["-c", "show log"]) => log,
                ("ndmc", ["-c", "show interface GigabitEthernet1"]) if matching => {
                    "connected: yes\naddress: 192.168.0.10"
                }
                ("ndmc", ["-c", "show interface GigabitEthernet1"]) => {
                    "connected: no\naddress: 192.168.0.10"
                }
                ("date", _) => "2026-10-03T01:16:13+0300",
                _ => return Err(io::ErrorKind::NotFound.into()),
            }
            .into())
        });
        let actual = discovery::discover(
            &firmware,
            false,
            &["eth0".into()],
            &[("eth0".into(), "192.168.0.10".parse().unwrap())],
        );
        assert_eq!(actual.is_ok(), matching);
        if let Ok(peers) = actual {
            assert_eq!(peers[0].addr.to_string(), "192.0.2.53:53");
            assert!(peers[0].expires.is_some());
        }
    }
}
#[test]
fn ignored_ppp_dns_is_tied_to_the_current_native_ipcp_session() {
    let interface="Interface, name = \"PPPoE0\"\n               id: PPPoE0\n             type: PPPoE\n        connected: yes\n          address: 192.0.2.5\n           global: yes\n        defaultgw: yes\n   security-level: public\n             ipv6:\n                  address: 2001:db8::1\n                  uptime: 999\n              session-id: 7\n           uptime: 60\n       session-id: 12650";
    let hosts = vec![("ppp0".into(), "192.0.2.5".parse().unwrap())];
    let configured = vec!["ppp0".into()];
    let main = std::collections::HashSet::from(["ppp0".into()]);
    let snapshot = |s: &str| ppp::active(s, &hosts, &configured, &main);
    let before = snapshot(interface);
    assert_eq!(before.len(), 1);
    let now = leases::parse_clock("2026-10-25T18:22:06+0300").unwrap();
    let log = |pid: u32, msg: &str| format!("I [Oct 25 18:21:06] pppd[{pid}]: {msg}\n");
    let mut evidence = String::new();
    for msg in [
        "PPP session is 12650",
        "Using interface ppp0",
        "Connect: ppp0 <--> eth3",
        "PAP authentication succeeded",
        "local  IP address 192.0.2.5",
        "remote IP address 192.0.2.1",
        "primary DNS address 192.0.2.53",
        "secondary DNS address 192.0.2.54",
    ] {
        evidence += &log(17, msg);
    }
    let peers = ppp::current(&evidence, now, &before, &before);
    assert_eq!(
        peers
            .iter()
            .map(|(dev, ip)| format!("{dev}/{ip}"))
            .collect::<Vec<_>>(),
        ["ppp0/192.0.2.53", "ppp0/192.0.2.54"]
    );
    let reads = AtomicUsize::new(0);
    let firmware = Script(|program: &str, args: &[&str]| {
        Ok(match (program, args) {
            ("ip", _) => "default dev ppp0",
            ("ndmc", ["-c", "show ip name-server"]) => "",
            ("ndmc", ["-c", "show interface"]) => {
                reads.fetch_add(1, Ordering::SeqCst);
                interface
            }
            ("ndmc", ["-c", "show log"]) => {
                assert_eq!(reads.load(Ordering::SeqCst), 1);
                &evidence
            }
            ("date", _) => "2026-10-25T18:22:06+0300",
            _ => return Err(io::ErrorKind::NotFound.into()),
        }
        .to_string())
    });
    let resolved = discovery::discover(&firmware, false, &configured, &hosts).unwrap();
    assert_eq!(
        resolved
            .iter()
            .map(|p| p.addr.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.53:53", "192.0.2.54:53"]
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    for (old, new) in [
        ("connected: yes", "connected: no"),
        ("type: PPPoE", "type: PPTP"),
        ("security-level: public", "security-level: private"),
        ("session-id: 12650", "session-id: 7"),
        ("uptime: 60", "uptime: 59"),
        ("uptime: 60", "uptime: 1000"),
    ] {
        assert!(
            ppp::current(
                &evidence,
                now,
                &before,
                &snapshot(&interface.replace(old, new))
            )
            .is_empty(),
            "{new}"
        );
    }
    for msg in [
        "IPCP terminated by peer",
        "Using interface ppp0",
        "secondary DNS address 127.0.0.1",
        "PPP session is 10",
        "local IP address 192.0.2.6",
        "Exit. reconnecting.",
    ] {
        assert!(
            ppp::current(&(evidence.clone() + &log(17, msg)), now, &before, &before).is_empty(),
            "{msg}"
        );
    }
    assert!(ppp::current(
        &(evidence.clone() + &log(18, "Using interface ppp0")),
        now,
        &before,
        &before
    )
    .is_empty());
    assert!(ppp::current(&evidence, now + time::Duration::hours(1), &before, &before).is_empty());
    assert!(ppp::current(
        &evidence.replace("pppd[17]", "other[17]"),
        now,
        &before,
        &before
    )
    .is_empty());
}
#[tokio::test]
async fn cancelled_firmware_reader_preserves_in_flight_discovery() {
    struct Delayed {
        count: AtomicUsize,
        entered: tokio::sync::Notify,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Source for Delayed {
        fn read(&self, _: &[discovery::History]) -> io::Result<discovery::Evidence> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3));
            Err(io::ErrorKind::NotFound.into())
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let source = Arc::new(Delayed {
        count: AtomicUsize::new(0),
        entered: Default::default(),
        release: Mutex::new(rx),
    });
    let session = Arc::new(
        Session::fixture(
            &json!({"enabled":true,"domains":[{"domain":"test"}]}),
            Arc::new(Environment {
                source: source.clone(),
                diagnostics: Default::default(),
                renewal: renew::Renewal::fixture(true),
                observer: Default::default(),
                leases: None,
                inform: Default::default(),
            }),
        )
        .unwrap(),
    );
    let first = {
        let session = session.clone();
        tokio::spawn(async move { session.discover(false).await })
    };
    source.entered.notified().await;
    first.abort();
    let _ = first.await;
    let second = {
        let session = session.clone();
        tokio::spawn(async move { session.discover(false).await })
    };
    tx.send(()).unwrap();
    assert!(second.await.unwrap().is_err());
    assert_eq!(source.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_dhcp_receipt_invalidates_cached_outage_without_manual_renew() {
    struct Physical {
        target: observer::Target,
        reads: AtomicUsize,
    }
    impl Source for Physical {
        fn read(&self, _: &[discovery::History]) -> io::Result<discovery::Evidence> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(discovery::Evidence::fixture(Vec::new()).with_fixture_target(&self.target))
        }
        fn target(
            &self,
            _: &discovery::Evidence,
            _: Option<&observer::Candidate>,
        ) -> Option<observer::Target> {
            Some(self.target.clone())
        }
    }
    let target = observer::Target {
        wan_key: "ip=192.0.2.10|route=eth9/".into(),
        candidate: observer::Candidate {
            iface: "ISP".into(),
            device: "eth9".into(),
            client: "192.0.2.10".parse().unwrap(),
        },
        index: 9,
        mac: [2, 0, 0, 0, 0, 1],
    };
    let source = Arc::new(Physical {
        target: target.clone(),
        reads: AtomicUsize::new(0),
    });
    let session = Session::fixture(
        &json!({"enabled":true,"domains":[{"domain":"test"}]}),
        Arc::new(Environment {
            source: source.clone(),
            diagnostics: Default::default(),
            renewal: renew::Renewal::fixture(true),
            observer: Default::default(),
            leases: None,
            inform: Default::default(),
        }),
    )
    .unwrap();
    let (reader, tx) = observer::Reader::fixture(target);
    session
        .env
        .observer
        .lock()
        .await
        .attach_fixture(&session.stopped.subscribe(), reader.clone());
    assert!(session.discover(false).await.is_err());
    tx.send_modify(|s| s.requests = 1);
    assert!(session.discover(false).await.is_err());
    assert_eq!(source.reads.load(Ordering::Relaxed), 1);

    let expiry = Instant::now() + Duration::from_secs(120);
    tx.send_modify(|s| {
        s.sequence = 1;
        s.receipt = Some(renew::capture::Receipt {
            observation: renew::capture::Observation::Dns {
                servers: vec!["192.0.2.53".parse().unwrap()],
                expires_at: expiry.into(),
                lease_seconds: 120,
            },
            observed_at: OffsetDateTime::now_utc(),
        });
    });
    let peers = session.discover(false).await.unwrap();
    assert_eq!(peers[0].addr.to_string(), "192.0.2.53:53");
    assert_eq!(peers[0].expires, Some(expiry));
    assert_eq!(session.discover(false).await.unwrap(), peers);
    assert_eq!(source.reads.load(Ordering::Relaxed), 2);

    tx.send_modify(|s| {
        s.sequence = 2;
        s.receipt = Some(renew::capture::Receipt {
            observation: renew::capture::Observation::Nak,
            observed_at: OffsetDateTime::now_utc(),
        });
    });
    assert!(session.discover(false).await.is_err());
    assert!(session.discover(false).await.is_err());
    assert_eq!(source.reads.load(Ordering::Relaxed), 3);
    assert!(session.cache.lock().await.history.is_empty());
}

#[tokio::test]
async fn provider_reports_invalid_upstream_answer_once_before_entering_backoff() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let env = Arc::new(Environment {
        source: Arc::new(Fixture {
            peer: Some(Peer {
                expires: None,
                device: String::new(),
                addr,
            }),
            count: AtomicUsize::new(0),
        }),
        diagnostics: Default::default(),
        renewal: renew::Renewal::fixture(true),
        observer: Default::default(),
        leases: None,
        inform: Default::default(),
    });
    let session =
        Session::fixture(&json!({"enabled":true,"domains":[{"domain":"test"}]}), env).unwrap();
    let query = nfqws2_dns::build_query("sample.test", 1, 9).unwrap();
    let task = tokio::spawn(async move {
        let mut received = [0u8; 512];
        let (n, client) = udp.recv_from(&mut received).await.unwrap();
        udp.send_to(&received[..n], client).await.unwrap();
    });
    let failures = Mutex::new(Vec::new());
    let slots = Semaphore::new(1);
    for _ in 0..2 {
        assert!(session
            .provider(&query, Duration::from_secs(2), &slots, |peer, _, error| {
                failures
                    .lock()
                    .unwrap()
                    .push((peer.to_owned(), error.kind()));
            })
            .await
            .is_err());
    }
    assert_eq!(
        failures.into_inner().unwrap(),
        [(addr.to_string(), io::ErrorKind::InvalidData)]
    );
    task.await.unwrap();
}

#[tokio::test]
async fn failed_provider_uses_timed_backoff_and_cached_discovery_failure() {
    let fixture = Arc::new(Fixture {
        count: AtomicUsize::new(0),
        peer: None,
    });
    let env = Arc::new(Environment {
        source: fixture.clone(),
        diagnostics: Default::default(),
        renewal: renew::Renewal::fixture(true),
        observer: Default::default(),
        leases: None,
        inform: Default::default(),
    });
    let session =
        Session::fixture(&json!({"enabled":true,"domains":[{"domain":"test"}]}), env).unwrap();
    let slots = Semaphore::new(1);
    for _ in 0..3 {
        assert!(session
            .provider(&[0; 12], Duration::from_secs(1), &slots, |_, _, _| {})
            .await
            .is_err());
    }
    assert_eq!(fixture.count.load(Ordering::SeqCst), 1);
    assert_eq!(session.status()["fallback_active"], true);
    assert!(session
        .renewal_request()
        .unwrap()
        .already_resolved()
        .await
        .is_none());
    assert_eq!(fixture.count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn shadow_discovery_reads_go_compatible_lease_from_panel_data_directory() {
    use std::{collections::BTreeMap, fs};

    struct InspectStored;
    impl Source for InspectStored {
        fn read(&self, retained: &[discovery::History]) -> io::Result<discovery::Evidence> {
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0].iface, "ISP");
            let saved = retained[0].to_saved();
            assert_eq!(saved.servers[0], "192.0.2.53:53".parse().unwrap());
            assert_eq!(saved.stamp, "Oct  3 11:00:00");
            assert!(saved.expires > Instant::now());
            // The storage receipt grants no traffic authority. This fixture
            // supplies no live firmware proof for the saved WAN.
            Ok(discovery::Evidence::fixture(Vec::new()))
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let db = nfqws2_store::Store::open(dir.path()).unwrap();
    let router = dir.path().join("router");
    let boot = router.join("proc/sys/kernel/random/boot_id");
    fs::create_dir_all(boot.parent().unwrap()).unwrap();
    fs::write(boot, "01234567-89ab-cdef-0123-456789abcdef\n").unwrap();
    fs::write(router.join("proc/uptime"), "43200.00 72000.00\n").unwrap();
    let file = lease_store::File::new(db.clone(), router.clone());
    file.update_leases(BTreeMap::from([(
        "ISP".into(),
        lease_store::Lease {
            wan_key: "ip=192.168.0.10|route=eth3/192.168.0.1".into(),
            client: "192.168.0.10".parse().unwrap(),
            servers: vec!["192.0.2.53:53".parse().unwrap()],
            expires: Instant::now() + Duration::from_secs(300),
            stamp: "Oct  3 11:00:00".into(),
            lease_seconds: 7200,
            observed_at: None,
        },
    )]))
    .unwrap();
    let receipt = dir.path().join("shadow-dns-leases.json");
    let before = fs::read(&receipt).unwrap();
    let mut env = Environment::new(Vec::new()).with_lease_file(db, &router);
    env.source = Arc::new(InspectStored);
    let session = Session::fixture(
        &json!({"enabled":true,"domains":[{"domain":"example.test"}]}),
        Arc::new(env),
    )
    .unwrap();
    assert!(session.discover(false).await.is_err());
    assert_eq!(session.status()["servers"], json!([]));
    assert_eq!(fs::read(receipt).unwrap(), before);
}
