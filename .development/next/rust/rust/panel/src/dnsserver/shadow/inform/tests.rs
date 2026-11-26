use super::*;
use std::{cell::Cell, collections::VecDeque, future::pending};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const DNS: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);
const MAC: [u8; 6] = [2, 3, 4, 5, 6, 7];
const ID: Identity = Identity {
    client: CLIENT,
    server: Some(SERVER),
    mac: MAC,
    xid: [1, 2, 3, 4],
};
const TARGET: Target<'static> = Target {
    device: "eth2.4094",
    index: 5,
    mac: MAC,
    client: CLIENT,
    server: Some(SERVER),
};

fn ack_options(server: Ipv4Addr) -> Vec<u8> {
    let mut options = vec![53, 1, 5, 54, 4];
    options.extend(server.octets());
    options
}

fn packet(options: &[u8], ipv4_options: bool) -> Vec<u8> {
    let header = if ipv4_options { 24 } else { 20 };
    let length = header + 8 + 240 + options.len();
    let mut packet = vec![0; length];
    packet[0] = 0x40 | (header as u8 / 4);
    packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    packet[8..10].copy_from_slice(&[64, 17]);
    packet[12..16].copy_from_slice(&SOURCE.octets());
    packet[16..20].copy_from_slice(&CLIENT.octets());
    let udp = &mut packet[header..];
    udp[..4].copy_from_slice(&[0, 67, 0, 68]);
    udp[4..6].copy_from_slice(&((length - header) as u16).to_be_bytes());
    let dhcp = &mut udp[8..];
    dhcp[..3].copy_from_slice(&[2, 1, 6]);
    dhcp[4..8].copy_from_slice(&ID.xid);
    dhcp[28..34].copy_from_slice(&MAC);
    dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    dhcp[240..].copy_from_slice(options);
    packet
}

fn positive(ipv4_options: bool) -> Vec<u8> {
    let mut options = ack_options(SERVER);
    options.extend([0, 6, 4]);
    options.extend(DNS.octets());
    options.push(255);
    packet(&options, ipv4_options)
}

fn accepted() -> Ack {
    Ack {
        server: SERVER,
        dns: vec![DNS],
    }
}

fn checksum(packet: &mut [u8]) {
    let header = usize::from(packet[0] & 15) * 4;
    let size = packet.len() - header;
    let pseudo = [
        packet[12..20].to_vec(),
        vec![0, 17],
        (size as u16).to_be_bytes().to_vec(),
        packet[header..].to_vec(),
    ]
    .concat();
    let mut sum = 0u32;
    for pair in pseudo.chunks(2) {
        sum += u32::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    packet[header + 6..header + 8].copy_from_slice(&checksum.to_be_bytes());
}

#[test]
fn parameter_request_matches_go_without_lease_assignment() {
    let mut expected = [0; 308];
    expected[..11].copy_from_slice(&[0, 68, 0, 67, 1, 52, 0, 0, 1, 1, 6]);
    expected[12..16].copy_from_slice(&[1, 2, 3, 4]);
    expected[20..24].copy_from_slice(&[192, 0, 2, 9]);
    expected[36..42].copy_from_slice(&MAC);
    expected[244..255].copy_from_slice(&[99, 130, 83, 99, 53, 1, 8, 55, 1, 6, 255]);
    assert_eq!(wire::request(ID), expected);
    assert_eq!(wire::request(Identity { server: None, ..ID }), expected);
}

#[test]
fn related_ack_requires_identity_and_uses_server_identifier_over_source() {
    let mut good = positive(true);
    good[24 + 8 + 24..24 + 8 + 28].copy_from_slice(&[192, 0, 2, 12]);
    assert_eq!(wire::reply(&good, ID), wire::Reply::Ack(accepted()));
    checksum(&mut good);
    let discovery = Identity { server: None, ..ID };
    assert_eq!(wire::reply(&good, discovery), wire::Reply::Ack(accepted()));
    assert!(matches!(
        wire::reply(
            &good,
            Identity {
                server: Some(SOURCE),
                ..ID
            }
        ),
        wire::Reply::Rejected(_)
    ));
    for offset in [0, 6, 9, 19, 25, 27, 36, 60] {
        let mut other = good.clone();
        other[offset] ^= 1;
        if offset == 0 || offset == 6 {
            // Incorrect version and more-fragments, respectively.
            other[offset] = if offset == 0 { 0x64 } else { 0x20 };
        }
        assert_eq!(
            wire::reply(&other, ID),
            wire::Reply::Unrelated,
            "offset {offset}"
        );
    }
    let mut other = good.clone();
    other[15] ^= 1;
    assert_eq!(
        wire::reply(&other, ID),
        wire::Reply::Rejected("invalid UDP checksum")
    );
    assert_eq!(
        wire::reply(&good[..good.len() - 1], ID),
        wire::Reply::Unrelated
    );
}

#[test]
fn ack_requires_clean_addresses_and_combines_only_valid_overloads() {
    let mut options = ack_options(SERVER);
    options.extend([52, 1, 3, 6, 1, 198, 255]);
    let mut good = packet(&options, false);
    let offset = 20 + 8;
    good[offset + 108..offset + 113].copy_from_slice(&[6, 2, 51, 100, 255]);
    good[offset + 44..offset + 48].copy_from_slice(&[6, 1, 53, 255]);
    assert_eq!(wire::reply(&good, ID), wire::Reply::Ack(accepted()));
    for (location, value) in [
        (offset + 108, 53),     // duplicate type, even outside primary options
        (offset + 112, 0),      // missing END in file
        (offset + 20 + 4, 127), // invalid giaddr
        (offset + 12, 127),     // wrong ciaddr
        (offset + 16, 192),     // lease assignment yiaddr
    ] {
        let mut bad = good.clone();
        bad[location] = value;
        assert!(
            matches!(wire::reply(&bad, ID), wire::Reply::Rejected(_)),
            "offset {location}"
        );
    }
    let discover = Identity { server: None, ..ID };
    for ip in [
        CLIENT,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        let mut invalid = ack_options(ip);
        invalid.extend([6, 4, 198, 51, 100, 53, 255]);
        assert!(matches!(
            wire::reply(&packet(&invalid, false), discover),
            wire::Reply::Rejected(_)
        ));
    }
}

#[derive(Default)]
struct Sockets {
    scripted: std::cell::RefCell<VecDeque<Vec<u8>>>,
    flood: bool,
    sends: Cell<usize>,
    reads: Cell<usize>,
}

impl Socket for Sockets {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        assert_eq!(packet, wire::request(ID));
        self.sends.set(self.sends.get() + 1);
        Ok(())
    }

    async fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        let response = self.scripted.borrow_mut().pop_front();
        if let Some(response) = response {
            let length = response.len().min(buffer.len());
            buffer[..length].copy_from_slice(&response[..length]);
            Ok(response.len())
        } else if self.flood {
            Ok(0)
        } else {
            pending().await
        }
    }
}

#[tokio::test(start_paused = true)]
async fn matching_rejection_does_not_end_exchange_and_reads_share_deadline() {
    let mut bad = positive(false);
    bad[20 + 8 + 16] = 192;
    let mut unrelated = bad.clone();
    unrelated[20 + 8 + 4] ^= 1;
    let socket = Sockets {
        scripted: VecDeque::from([bad, unrelated]).into(),
        ..Sockets::default()
    };
    let start = Instant::now();
    let deadline = start + Duration::from_millis(350);
    let err = exchange(&socket, ID, deadline, &Trace::default())
        .await
        .unwrap_err();
    assert_eq!(Instant::now(), deadline);
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(err.to_string().contains("unexpected address assignment"));
    assert_eq!(socket.sends.get(), 1);
    assert!(socket.reads.get() >= 4);

    let socket = Sockets {
        scripted: VecDeque::from([positive(false)]).into(),
        ..Sockets::default()
    };
    assert_eq!(
        exchange(&socket, ID, deadline + SLICE, &Trace::default())
            .await
            .unwrap(),
        accepted()
    );
    assert_eq!(socket.sends.get(), 1);
}

#[tokio::test]
async fn shadow_inform_socket_diagnostics_count_delivered_packets_without_exposing_payload() {
    let diagnostics = super::super::Diagnostics::default();
    diagnostics.set(true);
    let event = diagnostics.begin("dhcp.start", "fixture");
    let mut bad = positive(false);
    bad[20 + 8 + 16] = 192;
    let mut unrelated = positive(false);
    unrelated[20 + 8 + 4] ^= 1;
    let mut oversized = vec![0; BUFFER + 1];
    let marker = b"synthetic-payload-marker";
    oversized[..marker.len()].copy_from_slice(marker);
    let socket = Sockets {
        scripted: VecDeque::from([
            unrelated,
            bad.clone(),
            bad.clone(),
            bad.clone(),
            bad,
            oversized,
            positive(false),
        ])
        .into(),
        ..Sockets::default()
    };
    assert_eq!(
        exchange(&socket, ID, Instant::now() + WINDOW, &event.trace())
            .await
            .unwrap(),
        accepted()
    );
    assert_eq!(socket.sends.get(), 1);
    let report = diagnostics.read();
    let rows = report["attempts"][0]["events"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row["stage"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "dhcp.start",
            "dhcp.send",
            "dhcp.reject",
            "dhcp.reject",
            "dhcp.reject",
            "dhcp.receive",
        ]
    );
    assert!(rows[5]["message"]
        .as_str()
        .unwrap()
        .contains("получено=7, совпало с текущим запросом=5, отклонено=4"));
    assert!(rows[5]["message"]
        .as_str()
        .unwrap()
        .contains("после IP/firewall"));
    assert!(!report.to_string().contains("synthetic-payload-marker"));
}

#[tokio::test(start_paused = true)]
async fn shadow_inform_socket_diagnostics_report_canceled_receive_and_unsent_request() {
    struct NoSend;
    impl Socket for NoSend {
        async fn send(&self, _: &[u8]) -> io::Result<()> {
            Err(io::Error::other("synthetic backing socket error"))
        }
        async fn receive(&self, _: &mut [u8]) -> io::Result<usize> {
            panic!("did not send an INFORM request")
        }
    }
    let diagnostics = super::super::Diagnostics::default();
    diagnostics.set(true);
    let event = diagnostics.begin("dhcp.start", "fixture");
    let trace = event.trace();
    assert!(exchange(&NoSend, ID, Instant::now() + WINDOW, &trace)
        .await
        .is_err());
    let report = diagnostics.read();
    let rows = report["attempts"][0]["events"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["stage"], "dhcp.receive");
    assert!(rows[1]["message"]
        .as_str()
        .unwrap()
        .contains("получено=0, совпало с текущим запросом=0, отклонено=0"));
    assert!(!report
        .to_string()
        .contains("synthetic backing socket error"));

    let mut bad = positive(false);
    bad[20 + 8 + 16] = 192;
    let waiting = Sockets {
        scripted: VecDeque::from([bad]).into(),
        ..Sockets::default()
    };
    tokio::select! {
        _ = exchange(&waiting, ID, Instant::now() + WINDOW, &trace) => panic!("completed before cancellation"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => (),
    }
    let report = diagnostics.read();
    let rows = report["attempts"][0]["events"].as_array().unwrap();
    assert_eq!(rows[2]["stage"], "dhcp.send");
    assert_eq!(rows[3]["stage"], "dhcp.reject");
    assert_eq!(rows[4]["stage"], "dhcp.receive");
    assert!(rows[4]["message"]
        .as_str()
        .unwrap()
        .contains("получено=1, совпало с текущим запросом=1, отклонено=1"));
}

#[test]
fn shadow_wire_observation_reports_only_current_transaction_before_ip_filter() {
    let request = wire::request(ID);
    let mut outgoing = vec![0; 20 + request.len()];
    outgoing[0] = 0x45;
    outgoing[9] = 17;
    let total = (outgoing.len() as u16).to_be_bytes();
    outgoing[2..4].copy_from_slice(&total);
    outgoing[12..16].copy_from_slice(&ID.client.octets());
    outgoing[16..20].copy_from_slice(&ID.server.unwrap().octets());
    outgoing[20..].copy_from_slice(&request);
    let summary = wire::observation(&outgoing, ID, true).unwrap().summary();
    assert!(summary.contains("исходящий") && summary.contains("DHCP=INFORM"));
    assert!(wire::observation(&outgoing, ID, false).is_none());

    let mut incoming = positive(false);
    let summary = wire::observation(&incoming, ID, false).unwrap().summary();
    assert!(summary.contains("DHCP=ACK") && summary.contains("проверка ответа: OK"));
    assert!(
        !summary.contains("198.51.100.53"),
        "option 6 must stay out of the report"
    );

    let mut rejected = incoming.clone();
    rejected[20 + 8 + 236] ^= 1;
    let summary = wire::observation(&rejected, ID, false).unwrap().summary();
    assert!(summary.contains("проверка ответа: wrong DHCP cookie"));

    incoming[16..20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());
    assert!(matches!(wire::reply(&incoming, ID), wire::Reply::Unrelated));
    let summary = wire::observation(&incoming, ID, false).unwrap().summary();
    assert!(summary.contains("255.255.255.255:68"));
    assert!(summary.contains("пакет на WAN не соответствует адресу"));
    for offset in [20 + 8 + 4, 20 + 8 + 28] {
        let mut other = incoming.clone();
        other[offset] ^= 1;
        assert!(wire::observation(&other, ID, false).is_none());
    }
    incoming[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 99).octets());
    assert!(wire::observation(&incoming, ID, false).is_none());
    assert!(wire::observation(&incoming[..40], ID, false).is_none());
}

#[tokio::test(start_paused = true)]
async fn expired_and_canceled_probes_never_retry_and_flood_is_bounded() {
    let socket = Sockets {
        flood: true,
        ..Sockets::default()
    };
    let start = Instant::now();
    assert_eq!(
        exchange(&socket, ID, start, &Trace::default())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(socket.sends.get(), 0);
    assert_eq!(
        probe(TARGET, start, &Trace::default())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let invalid = Target {
        device: "br-lan",
        ..TARGET
    };
    assert_eq!(
        probe(invalid, start + WINDOW, &Trace::default())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let err = exchange(&socket, ID, start + WINDOW, &Trace::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("receive limit"));
    assert_eq!(socket.sends.get(), 1);
    assert_eq!(socket.reads.get(), MAX_READS);

    let waiting = Sockets::default();
    let trace = Trace::default();
    tokio::select! {
        _ = exchange(&waiting, ID, Instant::now() + WINDOW, &trace) => panic!("completed before cancellation"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => (),
    }
    assert_eq!((waiting.sends.get(), waiting.reads.get()), (1, 1));
    tokio::time::sleep(WINDOW).await;
    assert_eq!((waiting.sends.get(), waiting.reads.get()), (1, 1));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_bpf_is_reply_only_on_isolated_unix_datagrams() {
    use std::os::unix::net::UnixDatagram;

    let (sender, receiver) = UnixDatagram::pair().unwrap();
    linux::attach_filter(&receiver).unwrap();
    receiver.set_nonblocking(true).unwrap();
    let good = positive(true);
    for (offset, value) in [
        (0, 0x64),
        (0, 0x44),
        (6, 0x20),
        (7, 1),
        (9, 6),
        (25, 68),
        (27, 67),
    ] {
        let mut bad = good.clone();
        bad[offset] = value;
        sender.send(&bad).unwrap();
    }
    sender.send(&good).unwrap();
    let mut buffer = [0; BUFFER];
    let length = receiver.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..length], good);
    assert_eq!(
        receiver.recv(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
