use super::super::renew::capture::Receipt;
use super::*;

fn time(raw: &str) -> OffsetDateTime {
    super::super::leases::parse_clock(raw).unwrap()
}

fn target() -> Target {
    Target {
        wan_key: "ip=192.0.2.10|route=eth9/".into(),
        candidate: Candidate {
            iface: "ISP".into(),
            device: "eth9".into(),
            client: "192.0.2.10".parse().unwrap(),
        },
        index: 9,
        mac: [2, 0, 0, 0, 0, 1],
    }
}

#[test]
fn native_dhcp_current_receipt_supersedes_only_older_verified_same_wan_leases() {
    let target = target();
    let lease_seconds = Duration::from_secs(90);
    let expiry = Instant::now() + lease_seconds;
    let addr = "192.0.2.53:53".parse().unwrap();
    let evidence = |at| {
        let mut e = Evidence::fixture(vec![]).with_fixture_target(&target);
        e.history.push(History {
            key: target.wan_key.clone(),
            iface: "GigabitEthernet1".into(),
            client: target.candidate.client,
            stamp: "Oct  8 12:00:00".into(),
            lease_seconds: 90,
            observed_at: None,
            at: Some(at),
            expires: expiry,
            peers: vec![Peer {
                addr,
                device: "eth9".into(),
                expires: Some(expiry),
            }],
            bound: true,
            current: true,
        });
        e.fresh.push(("GigabitEthernet1".into(), at));
        e
    };
    let at = time("2026-10-08T12:00:00+0300");
    for offset in [-1, 0, 1] {
        let old = at + time::Duration::seconds(offset);
        for observation in [Observation::Nak, Observation::AckNoDns] {
            let receipt = Receipt {
                observation,
                observed_at: at,
            };
            let mut exact = evidence(old);
            let ppp = Peer {
                addr: "192.0.2.54:53".parse().unwrap(),
                device: "ppp0".into(),
                expires: None,
            };
            exact.peers.push(ppp.clone());
            let (resolved, retained) = exact.finish(Some((&target, &receipt)));
            let resolved = resolved.unwrap();
            assert_eq!(resolved.first(), Some(&ppp));
            assert_eq!(resolved.len(), 1 + usize::from(offset > 0));
            assert_eq!(retained.len(), usize::from(offset > 0));
        }
    }
    let old = at - time::Duration::seconds(1);
    let dns = "192.0.2.99".parse().unwrap();
    let receipt = Receipt {
        observation: Observation::Dns {
            servers: vec![target.candidate.client, dns],
            expires_at: expiry.into(),
            lease_seconds: 90,
        },
        observed_at: at,
    };
    let (resolved, retained) = evidence(old).finish(Some((&target, &receipt)));
    assert_eq!(
        resolved.unwrap(),
        vec![Peer {
            addr: SocketAddr::new(dns.into(), 53),
            device: "eth9".into(),
            expires: Some(expiry)
        }]
    );
    assert_eq!(retained[0].expires, expiry);
    let typed = evidence(old).finish_inform(Some((&target, &receipt)));
    assert!(matches!(typed.source, InformSource::NativeLease));
    assert_eq!(
        typed.native_applied.as_ref().map(|wan| wan.client),
        Some(target.candidate.client)
    );
    assert!(typed.ppp.is_empty());
    let ppp = Peer {
        addr,
        device: "ppp0".into(),
        expires: None,
    };
    let mut authoritative = Evidence::fixture(vec![ppp.clone()]);
    authoritative.inform_authoritative = true;
    let typed = authoritative.finish_inform(None);
    assert!(matches!(typed.source, InformSource::Authoritative));
    assert!(typed.ppp.is_empty());
    let typed = Evidence::fixture(vec![ppp.clone()]).finish_inform(None);
    assert!(matches!(
        typed.source,
        InformSource::Fallback {
            has_verified_peer: true
        }
    ));
    assert_eq!(typed.ppp, vec![ppp]);
    let mut stale = target.clone();
    stale.wan_key.push_str("|route=eth8/");
    let (resolved, _) = evidence(old).finish(Some((&stale, &receipt)));
    assert_eq!(resolved.unwrap()[0].addr, addr);
    let expired = Receipt {
        observation: Observation::Dns {
            servers: vec![dns],
            expires_at: Instant::now().into(),
            lease_seconds: 1,
        },
        ..receipt
    };
    let (resolved, history) = evidence(old).finish(Some((&target, &expired)));
    assert!(resolved.is_err());
    assert!(history.is_empty());
}

#[test]
fn native_dhcp_incomplete_firmware_ack_does_not_extend_verified_history() {
    struct FirmwareLog(bool);
    impl Runner for FirmwareLog {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            Ok(match (program, args) {
                    ("ip", _) => "default dev eth9",
                    ("date", _) => "2026-10-08T12:00:00+0300",
                    ("ndmc", ["-c", "show ip name-server" | "show interface"]) => "",
                    ("ndmc", ["-c", "show interface ISP"]) => "connected: yes\naddress: 192.0.2.10",
                    ("ndmc", ["-c", "show log"]) if self.0 => concat!(
                        "I [Oct  8 11:59:00] ndhcpc: ISP: received ACK for 192.0.2.10 from 192.0.2.1 lease 240\n",
                        "I [Oct  8 11:59:00] ndm: Dhcp::Client: obtained IP address 192.0.2.10/24\n",
                        "I [Oct  8 11:59:00] ndm: Dhcp::Client: name server 192.0.2.53 is ignored.\n",
                    ),
                    ("ndmc", ["-c", "show log"]) => "I [Oct  8 11:59:59] ndhcpc: ISP: received ACK for 192.0.2.10 from 192.0.2.1 lease 600",
                    _ => return Err(io::ErrorKind::NotFound.into()),
                }.into())
        }
    }
    let hosts = vec![("eth9".into(), "192.0.2.10".parse().unwrap())];
    let configured = ["eth9".to_owned()];
    let read = |log, old: &[History]| {
        collect(&FirmwareLog(log), false, &configured, &hosts, old)
            .unwrap()
            .finish(None)
    };
    let (peers, retained) = read(true, &[]);
    let peers = peers.unwrap();
    assert_eq!(peers[0].addr.to_string(), "192.0.2.53:53");
    let (reused, next) = read(false, &retained);
    assert_eq!(reused.unwrap(), peers);
    assert_eq!(retained[0].expires, next[0].expires);
}

#[test]
fn native_dhcp_saved_lease_requires_exact_live_wan_and_firmware_alias() {
    struct Firmware {
        routes: &'static str,
        identity: &'static str,
    }
    impl Runner for Firmware {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            let text = match (program, args) {
                ("ip", _) => self.routes,
                ("date", _) => "2026-10-08T12:00:00+0300",
                ("ndmc", ["-c", "show interface" | "show ip name-server" | "show log"]) => "",
                ("ndmc", ["-c", "show interface ISP"]) => self.identity,
                _ => return Err(io::ErrorKind::NotFound.into()),
            };
            Ok(text.into())
        }
    }
    let target = target();
    let expires = Instant::now() + Duration::from_secs(80);
    let server = "192.0.2.53:53".parse().unwrap();
    let saved = super::super::lease_store::Lease {
        wan_key: target.wan_key.clone(),
        client: target.candidate.client,
        servers: vec![server],
        expires,
        stamp: "Oct  8 11:59:00".into(),
        lease_seconds: 140,
        observed_at: None,
    };
    let imported = [History::from_saved("ISP".into(), saved.clone())];
    assert!(imported[0].peers[0].device.is_empty());
    assert!(!imported[0].current);

    let hosts = [(
        target.candidate.device.clone(),
        target.candidate.client.into(),
    )];
    let configured = [target.candidate.device];
    let resolve = |routes, identity| {
        let proof = collect(
            &Firmware { routes, identity },
            false,
            &configured,
            &hosts,
            &imported,
        )
        .unwrap();
        let checked = proof.has_authority_for_leases();
        (checked, proof.finish(None))
    };
    let exact = "connected: yes\naddress: 192.0.2.10";
    let (checked, (published, retained)) = resolve("default dev eth9 metric 1", exact);
    assert!(checked);
    assert_eq!(
        published.unwrap(),
        vec![Peer {
            addr: server,
            device: "eth9".into(),
            expires: Some(expires)
        }]
    );
    assert!(retained[0].to_saved() == saved);
    assert_eq!(retained[0].at, Some(time("2026-10-08T11:59:00+0300")));

    for identity in [
        "connected: no\naddress: 192.0.2.10",
        "connected: yes\naddress: 192.0.2.20",
    ] {
        let (checked, (published, retained)) = resolve("default dev eth9", identity);
        assert!(checked);
        assert!(published.is_err());
        assert!(retained[0].peers[0].device.is_empty());
        assert!(retained[0].to_saved() == saved);
    }
    let (checked, (published, retained)) = resolve("default via 192.0.2.1 dev eth9", exact);
    assert!(checked);
    assert!(published.is_err());
    assert!(retained.is_empty());
    let (checked, (published, retained)) = resolve("default dev awg0", exact);
    assert!(!checked);
    assert!(published.is_err());
    assert!(retained[0].to_saved() == saved);
}

const PHYSICAL: &str = "Interface, name = \"ISP\":\nid: ISP\ntype: GigabitEthernet\nconnected: yes\nglobal: yes\ndefaultgw: yes\nsecurity-level: public\naddress: 192.0.2.10\n";

struct InformFirmware<'a> {
    routes: &'a str,
    alias: &'a str,
    physical: &'a str,
    clock: &'a str,
}

impl Runner for InformFirmware<'_> {
    fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
        let text = match (program, args) {
            ("ip", _) => self.routes,
            ("date", _) => self.clock,
            ("ndmc", ["-c", "show ip name-server"]) => "",
            ("ndmc", ["-c", "show interface"]) => self.physical,
            ("ndmc", ["-c", "show interface Replay" | "show interface Ring" | "show interface SavedAlias" | "show interface LocalServer"]) => self.alias,
            ("ndmc", ["-c", "show interface WrongOwner"]) => "connected: yes\naddress: 192.0.2.66",
            ("ndmc", ["-c", "show log"]) => concat!(
                "I [Oct  6 11:59:59] ndhcpc: Replay: received ACK for 192.0.2.10 from 192.0.2.1 lease 40\n",
                "I [Oct  8 11:59:59] ndhcpc: Ring: received ACK for 192.0.2.10 from 192.0.2.2 lease 600\n",
                "I [Oct  8 11:59:59] ndhcpc: LocalServer: received ACK for 192.0.2.10 from 192.0.2.5 lease 600\n",
                "I [Oct  8 11:59:59] ndhcpc: WrongOwner: received ACK for 192.0.2.10 from 192.0.2.3 lease 600\n",
            ),
            _ => return Err(io::ErrorKind::NotFound.into()),
        };
        Ok(text.into())
    }
}

#[test]
fn native_dhcp_inform_learns_current_ring_server_without_dns_or_live_lease() {
    let hosts = [
        ("eth9".into(), "192.0.2.10".parse().unwrap()),
        ("br-lan".into(), "192.0.2.5".parse().unwrap()),
    ];
    let cfg = ["eth9".into()];
    let known = [KnownTarget {
        iface: "SavedAlias".into(),
        wan_key: "ip=192.0.2.10|route=eth9/".into(),
        client: "192.0.2.10".parse().unwrap(),
        server: "192.0.2.4".parse().unwrap(),
        stamp: String::new(),
        observed_at_epoch: None,
    }];
    let fw = InformFirmware {
        routes: "default dev eth9",
        alias: "connected: yes\naddress: 192.0.2.10",
        physical: PHYSICAL,
        clock: "2026-10-08T12:00:00+0300",
    };
    let read = |firmware: &InformFirmware<'_>| {
        collect_with_inform(
            firmware,
            false,
            &cfg,
            &hosts,
            Query {
                retained: &[],
                known: &known,
                deadline: Instant::now() + Duration::from_secs(1),
                trace: &Trace::default(),
            },
        )
        .unwrap()
    };
    let mut evidence = read(&fw);
    evidence.bind_inform(&hosts, |_| Ok((9, [2, 0, 0, 0, 0, 1])));
    let finished = evidence.finish_inform(None);
    assert!(finished.result.is_err());
    assert!(finished.history.is_empty());
    assert!(matches!(
        finished.source,
        InformSource::Fallback {
            has_verified_peer: false
        }
    ));
    assert_eq!(
        finished
            .inform
            .owners
            .iter()
            .map(|wan| wan.iface.as_str())
            .collect::<Vec<_>>(),
        ["ISP", "SavedAlias", "Replay", "Ring"]
    );
    assert_eq!(
        finished.inform.wan_ips,
        ["192.0.2.10".parse::<Ipv4Addr>().unwrap()]
    );
    assert_eq!(finished.inform.local.len(), 2);
    assert_eq!(
        finished
            .inform
            .ring
            .iter()
            .map(|hint| hint.server.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.1", "192.0.2.2"]
    );
    assert_eq!(
        finished.inform.ring[1].observed_at_epoch,
        Some(time("2026-10-08T11:59:59+0300").unix_timestamp())
    );
    let alias = &finished.inform.owners[3];
    let confirm = |firmware: &InformFirmware<'_>, index| {
        confirm_inform_with(
            firmware,
            &cfg,
            || Ok(hosts.to_vec()),
            alias,
            Instant::now() + Duration::from_secs(1),
            |_| Ok((index, [2, 0, 0, 0, 0, 1])),
        )
    };
    assert!(confirm(&fw, 9));
    assert!(!confirm(&fw, 8));
    assert!(!confirm(
        &InformFirmware {
            routes: "default via 192.0.2.1 dev eth9",
            ..fw
        },
        9
    ));
    assert!(!confirm(
        &InformFirmware {
            alias: "connected: yes\naddress: 192.0.2.66",
            ..fw
        },
        9
    ));
    assert!(!confirm(&InformFirmware { physical: "", ..fw }, 9));
    struct Switch<'a>(InformFirmware<'a>, std::sync::atomic::AtomicBool);
    impl Runner for Switch<'_> {
        fn run(&self, program: &str, args: &[&str], deadline: Instant) -> io::Result<String> {
            if program == "ip" && self.1.swap(true, std::sync::atomic::Ordering::Relaxed) {
                return Ok("default via 192.0.2.1 dev eth9".into());
            }
            self.0.run(program, args, deadline)
        }
    }
    let switching = Switch(InformFirmware { ..fw }, false.into());
    assert!(!confirm_inform_with(
        &switching,
        &cfg,
        || Ok(hosts.to_vec()),
        alias,
        Instant::now() + Duration::from_secs(1),
        |_| Ok((9, [2, 0, 0, 0, 0, 1]))
    ));

    let mut ambiguous = hosts.to_vec();
    ambiguous.push(("eth8".into(), "192.0.2.10".parse().unwrap()));
    let mut evidence = read(&fw);
    evidence.bind_inform(&ambiguous, |_| Ok((9, [2, 0, 0, 0, 0, 1])));
    assert!(evidence.inform.owners.is_empty());
    assert!(evidence.inform.ring.is_empty());
}

#[test]
fn shadow_diagnostics_reports_observed_firmware_stages_without_raw_output() {
    struct Marker;
    impl Runner for Marker {
        fn run(&self, program: &str, args: &[&str], _: Instant) -> io::Result<String> {
            Ok(match (program, args) {
                ("ip", _) => "default dev eth9\ncommand-output-fixture.example",
                ("ndmc", ["-c", "show ip name-server"]) => "server:\naddress: 192.0.2.53\nservice: DHCP client\ninterface: Wrong\ncommand-output-fixture.example",
                ("ndmc", ["-c", "show interface Wrong"]) => "connected: no\naddress: 192.0.2.10",
                ("ndmc", ["-c", "show interface"]) => "",
                ("ndmc", ["-c", "show log"]) => "I [Oct  8 11:59:59] unrelated: command-output-fixture.example",
                ("date", _) => "2026-10-08T12:00:00+0300",
                _ => return Err(io::ErrorKind::NotFound.into()),
            }.into())
        }
    }
    let report = super::super::Diagnostics::default();
    report.set(true);
    let event = report.begin("discovery.start", "fixture");
    let hosts = [("eth9".into(), "192.0.2.10".parse().unwrap())];
    let trace = event.trace();
    let evidence = collect_with_inform(
        &Marker,
        false,
        &["eth9".into()],
        &hosts,
        Query {
            retained: &[],
            known: &[],
            deadline: Instant::now() + Duration::from_secs(1),
            trace: &trace,
        },
    )
    .unwrap();
    assert!(evidence.peers.is_empty());
    let log = report.read();
    let entries = log["attempts"][0]["events"].as_array().unwrap();
    for stage in [
        "wan.addresses",
        "native.command",
        "wan.verify",
        "native.dns",
        "wan.default",
        "native.leases",
        "native.log.summary",
    ] {
        assert!(
            entries.iter().any(|entry| entry["stage"] == stage),
            "missing {stage}"
        );
    }
    assert!(!log.to_string().contains("command-output-fixture.example"));
    assert!(log["in_progress"].as_bool().unwrap());
}
