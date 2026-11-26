use super::*;

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 12);
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const MAC: [u8; 6] = [2, 1, 2, 3, 4, 5];
const HEADER: usize = 24;
const DHCP: usize = HEADER + 8;

fn recheck(data: &mut [u8]) {
    data[10..12].fill(0);
    data[HEADER + 6..HEADER + 8].fill(0);
    let header = !fold_checksum(checksum_sum(&data[..HEADER]));
    data[10..12].copy_from_slice(&header.to_be_bytes());
    let udp = &data[HEADER..];
    let pseudo = checksum_sum(&data[12..20]) + 17 + udp.len() as u32;
    let check = !fold_checksum(pseudo + checksum_sum(udp));
    // An arithmetic zero checksum is sent as all ones.
    data[HEADER + 6..HEADER + 8]
        .copy_from_slice(&(if check == 0 { 0xffff } else { check }).to_be_bytes());
}

fn frame(
    outgoing: bool,
    xid: u8,
    source: Ipv4Addr,
    target: Ipv4Addr,
    assigned: Ipv4Addr,
    current: Ipv4Addr,
    options: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; DHCP + 240 + options.len()];
    let len = bytes.len() as u16;
    bytes[0] = 0x46; // UDP follows four bytes of IPv4 options.
    bytes[2..4].copy_from_slice(&len.to_be_bytes());
    bytes[8..10].copy_from_slice(&[64, 17]);
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&target.octets());
    let (src, dst, op) = if outgoing {
        (68u16, 67u16, 1)
    } else {
        (67, 68, 2)
    };
    bytes[HEADER..HEADER + 2].copy_from_slice(&src.to_be_bytes());
    bytes[HEADER + 2..HEADER + 4].copy_from_slice(&dst.to_be_bytes());
    bytes[HEADER + 4..HEADER + 6].copy_from_slice(&(len - HEADER as u16).to_be_bytes());
    bytes[DHCP..DHCP + 3].copy_from_slice(&[op, 1, 6]);
    bytes[DHCP + 7] = xid;
    bytes[DHCP + 12..DHCP + 16].copy_from_slice(&current.octets());
    bytes[DHCP + 16..DHCP + 20].copy_from_slice(&assigned.octets());
    bytes[DHCP + 28..DHCP + 34].copy_from_slice(&MAC);
    bytes[DHCP + 236..DHCP + 240].copy_from_slice(&[99, 130, 83, 99]);
    bytes[DHCP + 240..].copy_from_slice(options);
    recheck(&mut bytes);
    bytes
}

fn request(xid: u8) -> Vec<u8> {
    frame(true, xid, CLIENT, SERVER, ANY, CLIENT, &[53, 1, 3, 255])
}

fn selecting(xid: u8, server: Ipv4Addr) -> Vec<u8> {
    let mut options = vec![53, 1, 3, 50, 4];
    options.extend_from_slice(&CLIENT.octets());
    options.extend_from_slice(&[54, 4]);
    options.extend_from_slice(&server.octets());
    options.push(255);
    frame(true, xid, ANY, BROADCAST, ANY, ANY, &options)
}

fn response(xid: u8, server: Ipv4Addr, kind: u8, tail: &[u8]) -> Vec<u8> {
    let mut options = vec![53, 1, kind, 54, 4];
    options.extend_from_slice(&server.octets());
    options.extend_from_slice(&[51, 4]);
    options.extend_from_slice(&u32::MAX.to_be_bytes());
    options.extend_from_slice(tail);
    options.push(255);
    frame(
        false,
        xid,
        server,
        CLIENT,
        if kind == 5 { CLIENT } else { ANY },
        ANY,
        &options,
    )
}

#[test]
fn passive_renewal_requires_exact_outgoing_request_and_bounded_dns_lease() {
    let mut tracker = Tracker::new(CLIENT, MAC).unwrap();
    let now = Instant::now();
    let mut option6 = vec![6, 44];
    option6.extend_from_slice(&[198, 51, 100, 1]);
    for server in 1..=10 {
        option6.extend_from_slice(&[198, 51, 100, server]);
    }
    let mut ack = response(1, SERVER, 5, &option6);
    assert_eq!(tracker.packet(&ack, false, now), None);
    assert_eq!(tracker.packet(&request(1), false, now), None);
    assert_eq!(tracker.packet(&ack, false, now), None);
    assert_eq!(tracker.packet(&request(1), true, now), None);
    // A relay's IP is part of the wire checksum, not an invented DHCP server.
    ack[12..16].copy_from_slice(&OTHER.octets());
    ack[DHCP + 24..DHCP + 28].copy_from_slice(&OTHER.octets());
    recheck(&mut ack);
    let observed = now + Duration::from_secs(7);
    assert_eq!(
        tracker.packet(&ack, false, observed),
        Some(Observation::Dns {
            servers: (1..=8).map(|i| Ipv4Addr::new(198, 51, 100, i)).collect(),
            expires_at: now + Duration::from_secs(u64::from(MAX_LEASE_SECS)),
            lease_seconds: MAX_LEASE_SECS,
        })
    );
    assert_eq!(tracker.packet(&ack, false, observed), None);
}

#[test]
fn passive_tracker_discards_malformed_and_off_target_replies() {
    let mut tracker = Tracker::new(CLIENT, MAC).unwrap();
    let now = Instant::now();
    let ack = response(7, SERVER, 5, &[6, 4, 198, 51, 100, 1]);
    let mut other_client = request(7);
    other_client[DHCP + 28] ^= 2;
    recheck(&mut other_client);
    tracker.packet(&other_client, true, now);
    assert_eq!(tracker.packet(&ack, false, now), None);
    tracker.packet(&request(7), true, now);
    for (offset, byte) in [
        (0, 0x65),
        (6, 0x20),
        (9, 6),
        (15, CLIENT.octets()[3]),
        (19, 99),
        (HEADER + 1, 68),
        (DHCP, 1),
        (DHCP + 2, 5),
        (DHCP + 7, 8),
        (DHCP + 19, 99),
        (DHCP + 28, 0x06),
        (DHCP + 237, 0),
        (DHCP + 241, 99),
    ] {
        let mut invalid = ack.clone();
        invalid[offset] = byte;
        recheck(&mut invalid);
        assert_eq!(
            tracker.packet(&invalid, false, now),
            None,
            "offset {offset}"
        );
    }
    for n in 0..ack.len() {
        assert_eq!(tracker.packet(&ack[..n], false, now), None);
    }
    let mut corrupt = ack.clone();
    corrupt[HEADER + 7] ^= 1;
    assert_eq!(tracker.packet(&corrupt, false, now), None);
    corrupt.clone_from(&ack);
    corrupt[10] ^= 1;
    assert_eq!(tracker.packet(&corrupt, false, now), None);
    for option in [
        &[6, 0][..],
        &[6, 1, 198],
        &[6, 4, 127, 0, 0, 1],
        &[53, 1, 5],
    ] {
        assert_eq!(
            tracker.packet(&response(7, SERVER, 5, option), false, now),
            None
        );
    }
    assert!(matches!(
        tracker.packet(&ack, false, now),
        Some(Observation::Dns { .. })
    ));
}

#[test]
fn selected_server_and_no_dns_or_nak_consume_only_correlated_requests() {
    let mut tracker = Tracker::new(CLIENT, MAC).unwrap();
    let now = Instant::now();
    tracker.packet(&selecting(3, SERVER), true, now);
    tracker.packet(&selecting(3, OTHER), true, now);
    assert_eq!(
        tracker.packet(&response(3, OTHER, 6, &[]), false, now),
        None
    );
    let nak = response(3, SERVER, 6, &[]);
    assert_eq!(tracker.packet(&nak, false, now), Some(Observation::Nak));
    assert_eq!(tracker.packet(&nak, false, now), None);
    tracker.packet(&selecting(3, OTHER), true, now);
    assert_eq!(
        tracker.packet(&response(3, SERVER, 5, &[]), false, now),
        None
    );
    assert_eq!(
        tracker.packet(&response(3, OTHER, 5, &[]), false, now),
        Some(Observation::AckNoDns)
    );
    assert_eq!(
        tracker.packet(&response(3, OTHER, 5, &[]), false, now),
        None
    );
}

#[test]
fn pending_window_and_eviction_survive_retransmit_and_late_reply() {
    let mut tracker = Tracker::new(CLIENT, MAC).unwrap();
    let now = Instant::now();
    tracker.packet(&request(1), true, now);
    tracker.packet(&request(1), true, now + Duration::from_secs(119));
    let after = now + PENDING_TTL;
    assert_eq!(
        tracker.packet(&response(1, SERVER, 5, &[]), false, after),
        None
    );
    for id in 2..=10 {
        tracker.packet(&request(id), true, after);
    }
    assert_eq!(tracker.pending.iter().flatten().count(), 8);
    assert_eq!(
        tracker.packet(&response(2, SERVER, 5, &[]), false, after),
        None
    );
    assert_eq!(
        tracker.packet(&response(9, SERVER, 5, &[]), false, after),
        Some(Observation::AckNoDns)
    );
    assert_eq!(
        tracker.packet(&response(8, SERVER, 5, &[]), false, after),
        None
    );
    assert_eq!(
        tracker.packet(&response(10, SERVER, 5, &[]), false, after),
        Some(Observation::AckNoDns)
    );
}

#[test]
fn concatenated_dns_options_include_file_and_server_overload() {
    let mut tracker = Tracker::new(CLIENT, MAC).unwrap();
    let now = Instant::now();
    tracker.packet(&request(1), true, now);
    let mut ack = response(1, SERVER, 5, &[52, 1, 3, 6, 2, 198, 51]);
    ack[DHCP + 108..DHCP + 113].copy_from_slice(&[6, 2, 100, 1, 255]);
    ack[DHCP + 44..DHCP + 51].copy_from_slice(&[6, 4, 198, 51, 100, 2, 255]);
    recheck(&mut ack);
    assert_eq!(
        tracker.packet(&ack, false, now),
        Some(Observation::Dns {
            servers: vec![
                Ipv4Addr::new(198, 51, 100, 1),
                Ipv4Addr::new(198, 51, 100, 2)
            ],
            expires_at: now + Duration::from_secs(u64::from(MAX_LEASE_SECS)),
            lease_seconds: MAX_LEASE_SECS,
        })
    );
}
