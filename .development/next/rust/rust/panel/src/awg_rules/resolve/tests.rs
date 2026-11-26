use super::*;
use std::{
    fs,
    io::Write,
    net::{TcpListener, UdpSocket},
    thread,
};

fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn name(host: &str) -> Vec<u8> {
    let q = nfqws2_dns::build_query(host, 1, 1).unwrap();
    q[12..q.len() - 4].to_vec()
}
fn response(q: &[u8], answers: usize) -> Vec<u8> {
    let mut r = nfqws2_dns::response_error(q, 0);
    r[6..8].copy_from_slice(&(answers as u16).to_be_bytes());
    r
}
fn rr(packet: &mut Vec<u8>, owner: &[u8], kind: u16, data: &[u8]) {
    packet.extend_from_slice(owner);
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.extend_from_slice(data);
}
fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut packet = [0; 512];
    let (len, peer) = socket.recv_from(&mut packet).unwrap();
    (packet[..len].to_owned(), peer)
}

#[test]
fn dual_stack_queries_both_families_and_keeps_valid_nodata_separate_from_transport_failure() {
    let v6 = "2001:db8:1234::18".parse::<std::net::Ipv6Addr>().unwrap();
    for (send_v6, rcode, expected) in [
        (true, 0, Some(2usize)),
        (false, 0, Some(1)),
        (false, 2, None),
    ] {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = udp.local_addr().unwrap();
        let task = thread::spawn(move || {
            for kind in [1, 28] {
                let (query, client) = receive(&udp);
                assert_eq!(
                    nfqws2_dns::query_domain(&query).unwrap(),
                    ("dual.test".into(), kind)
                );
                let mut wire = if kind == 1 || send_v6 {
                    response(&query, 1)
                } else {
                    nfqws2_dns::response_error(&query, rcode)
                };
                if kind == 1 {
                    rr(&mut wire, &[0xc0, 12], 1, &[192, 0, 2, 18]);
                } else if send_v6 {
                    rr(&mut wire, &[0xc0, 12], 28, &v6.octets());
                }
                udp.send_to(&wire, client).unwrap();
            }
        });
        let result = addresses("dual.test", &[server], until(), true, true);
        if let Some(count) = expected {
            let ips = result.unwrap();
            assert_eq!(ips.len(), count);
            assert_eq!(ips[0], IpAddr::from([192, 0, 2, 18]));
            if count == 2 {
                assert_eq!(ips[1], IpAddr::V6(v6));
            }
        } else {
            assert!(result.is_err());
        }
        task.join().unwrap();
    }
}
fn accept(listener: &TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = until();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(e) => panic!("loopback DNS TCP: {e}"),
        }
    }
}
#[test]
fn udp_truncation_tcp_cname_and_complete_address_set_share_one_selected_resolver() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).unwrap();
    let server = thread::spawn(move || {
        let (q, client) = receive(&udp);
        assert_eq!(nfqws2_dns::query_domain(&q).unwrap().0, "exact.test");
        let mut tc = response(&q, 0);
        tc[2] |= 2;
        udp.send_to(&tc, client).unwrap();
        let mut conn = accept(&tcp);
        conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut len = [0; 2];
        conn.read_exact(&mut len).unwrap();
        let mut again = vec![0; u16::from_be_bytes(len) as usize];
        conn.read_exact(&mut again).unwrap();
        assert_eq!(q, again);
        let mut first = response(&q, 1);
        rr(&mut first, &[0xc0, 12], 5, &name("intermediate.test"));
        first[11] = 1;
        rr(
            &mut first,
            &name("padding.test"),
            65280,
            &vec![0; 48 * 1024],
        );
        conn.write_all(&(first.len() as u16).to_be_bytes()).unwrap();
        conn.write_all(&first).unwrap();
        let (q, client) = receive(&udp);
        assert_eq!(nfqws2_dns::query_domain(&q).unwrap().0, "intermediate.test");
        let mut final_reply = response(&q, 5);
        rr(&mut final_reply, &name("other.test"), 1, &[192, 0, 2, 99]);
        rr(&mut final_reply, &name("edge.test"), 1, &[10, 8, 0, 2]);
        rr(&mut final_reply, &[0xc0, 12], 5, &name("EdGe.test"));
        rr(&mut final_reply, &name("edge.test"), 1, &[10, 8, 0, 1]);
        rr(&mut final_reply, &name("edge.test"), 1, &[10, 8, 0, 2]);
        udp.send_to(&final_reply, client).unwrap();
    });
    assert_eq!(
        thread::Builder::new()
            .stack_size(192 * 1024)
            .spawn(move || ipv4("Exact.Test.", &[addr], until()))
            .unwrap()
            .join()
            .unwrap()
            .unwrap(),
        [Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(10, 8, 0, 2)]
    );
    server.join().unwrap();
}
#[test]
fn malformed_conflicting_or_oversized_sets_never_return_a_subset() {
    let q = nfqws2_dns::build_query("one.test", 1, 7).unwrap();
    let source = &[0xc0, 12];
    let mut many = response(&q, 300);
    for i in 0..300u16 {
        rr(&mut many, source, 1, &[198, 51, (i >> 8) as u8, i as u8]);
    }
    assert_eq!(nfqws2_dns::exact_ipv4_step(&many).unwrap().1.len(), 300);
    let mut malformed = many;
    malformed[6..8].copy_from_slice(&301u16.to_be_bytes());
    rr(&mut malformed, source, 1, &[1, 2, 3]);
    assert!(nfqws2_dns::exact_ipv4_step(&malformed).is_err());
    malformed[6..8].copy_from_slice(&513u16.to_be_bytes());
    assert!(nfqws2_dns::exact_ipv4_step(&malformed).is_err());
    for (owner, kind, value) in [
        (source.to_vec(), 5, name("two.test")),
        (source.to_vec(), 1, vec![192, 0, 2, 1]),
        (name("edge.test"), 5, name("one.test")),
    ] {
        let mut conflict = response(&q, 2);
        rr(&mut conflict, source, 5, &name("edge.test"));
        rr(&mut conflict, &owner, kind, &value);
        assert!(nfqws2_dns::exact_ipv4_step(&conflict).is_err());
    }
    let mut negative = nfqws2_dns::blocked_reply(&q).unwrap();
    negative[3] &= 0xf0;
    assert_eq!(
        nfqws2_dns::exact_ipv4_step(&negative).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let mut glue = response(&q, 0);
    glue[11] = 1;
    rr(&mut glue, source, 1, &[192, 0, 2, 2]);
    assert_eq!(
        nfqws2_dns::exact_ipv4_step(&glue).unwrap(),
        (vec![], vec![])
    );
}
#[test]
fn failures_and_negative_answers_never_replace_dns_policy_with_a_partial_set() {
    for case in ["nxdomain", "nodata", "unsafe", "numeric-alias", "servfail"] {
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoints = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        let responder = thread::spawn(move || {
            let (q, client) = receive(&first);
            let mut r = response(&q, 0);
            match case {
                "nxdomain" => r[3] |= 3,
                "nodata" => (),
                "unsafe" => {
                    r[7] = 2;
                    rr(&mut r, &[0xc0, 12], 1, &[192, 0, 2, 1]);
                    rr(&mut r, &[0xc0, 12], 1, &[127, 0, 0, 1]);
                }
                "numeric-alias" => {
                    r[7] = 2;
                    rr(&mut r, &[0xc0, 12], 5, &name("0x7f.1"));
                    rr(&mut r, &name("0x7f.1"), 1, &[192, 0, 2, 1]);
                }
                _ => r[3] |= 2,
            }
            first.send_to(&r, client).unwrap();
            if case == "servfail" {
                let (q, client) = receive(&second);
                let mut r = response(&q, 1);
                rr(&mut r, &[0xc0, 12], 1, &[192, 0, 2, 10]);
                second.send_to(&r, client).unwrap();
            }
            second
        });
        let resolved = ipv4("private.test", &endpoints, until());
        match case {
            "servfail" => assert_eq!(resolved.unwrap(), [Ipv4Addr::new(192, 0, 2, 10)]),
            "unsafe" | "numeric-alias" => {
                assert_eq!(resolved.unwrap_err().kind(), io::ErrorKind::InvalidData)
            }
            _ => assert_eq!(resolved.unwrap_err().kind(), io::ErrorKind::NotFound),
        }
        let second = responder.join().unwrap();
        second.set_nonblocking(true).unwrap();
        assert_eq!(
            second.recv(&mut [0; 512]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
#[test]
fn router_config_uses_only_numeric_servers_and_exact_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resolv.conf");
    fs::write(&path,"search example.test\nnameserver public.invalid\nnameserver 0.0.0.0\nnameserver 127.0.0.1 # local\nnameserver 127.0.0.1\nnameserver 2001:db8::1 ; v6\n").unwrap();
    assert_eq!(
        nameservers(&path).unwrap(),
        [
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:53".parse().unwrap()
        ]
    );
    for contents in ["options timeout:1".into(), "x".repeat(16 * 1024 + 1)] {
        fs::write(&path, contents).unwrap();
        assert!(nameservers(&path).is_err());
    }
    for name in [
        "*.example",
        "domain:example",
        "",
        ".",
        "a..b",
        "1.2.3.4",
        "127.1",
        "full:example.test",
        ".suffix",
        "x/y",
        "name\n",
        "a.-b",
    ] {
        assert!(exact_name(name).is_err(), "{name}");
    }
    for bad in [
        [0, 1, 2, 3],
        [127, 0, 0, 1],
        [169, 254, 1, 2],
        [239, 1, 2, 3],
        [250, 1, 2, 3],
        [255; 4],
    ] {
        assert!(!routable(bad.into()));
    }
    assert!(routable(Ipv4Addr::new(10, 8, 0, 1).into()));
    for ip in ["::", "::1", "fe80::7", "ff02::1", "::ffff:192.0.2.4"] {
        assert!(!routable(ip.parse().unwrap()), "{ip}");
    }
}
#[test]
fn cname_cycle_spanning_two_udp_requests_is_rejected() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let server = thread::spawn(move || {
        for (owner, alias) in [("one.test", "edge.test"), ("edge.test", "one.test")] {
            let (q, client) = receive(&socket);
            assert_eq!(nfqws2_dns::query_domain(&q).unwrap().0, owner);
            let mut r = response(&q, 1);
            rr(&mut r, &[0xc0, 12], 5, &name(alias));
            socket.send_to(&r, client).unwrap();
        }
    });
    assert_eq!(
        lookup("one.test", addr, until(), 1).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    server.join().unwrap();
}
#[test]
fn fragmented_tcp_header_cannot_extend_the_lookup_deadline() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).unwrap();
    let (finish, release) = std::sync::mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (q, client) = receive(&udp);
        let mut tc = response(&q, 0);
        tc[2] |= 2;
        udp.send_to(&tc, client).unwrap();
        let mut conn = accept(&tcp);
        thread::sleep(Duration::from_millis(120));
        conn.write_all(&[0]).unwrap();
        let _ = release.recv_timeout(Duration::from_secs(2));
    });
    let start = Instant::now();
    let result = lookup("timeout.test", addr, start + Duration::from_millis(350), 1);
    finish.send(()).unwrap();
    server.join().unwrap();
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_millis(1600));
}
